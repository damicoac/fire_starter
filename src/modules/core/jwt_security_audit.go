package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type JWTSecurityAuditResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type JWTSecurityAudit struct {
	BaseModule
	Target  string
	results []JWTSecurityAuditResult
}

func NewJWTSecurityAudit(target string) *JWTSecurityAudit {
	return &JWTSecurityAudit{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *JWTSecurityAudit) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var jwtNonePayloads = []string{
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmaXJlc3RhcnRlcl9hZG1pbiIsInNjb3BlIjoiYWRtaW4iLCJmaXJlc3RhcnRlcl9jbGFpbSI6ImFsbG93In0.",
	"eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmaXJlc3RhcnRlcl9hZG1pbiIsInNjb3BlIjoiYWRtaW4iLCJmaXJlc3RhcnRlcl9jbGFpbSI6ImFsbG93In0.",
	"eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmaXJlc3RhcnRlcl9hZG1pbiIsInNjb3BlIjoiYWRtaW4iLCJmaXJlc3RhcnRlcl9jbGFpbSI6ImFsbG93In0.",
}

const (
	jwtInvalidSignedPayload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXJlc3RhcnRlcl9hZG1pbiIsInNjb3BlIjoiYWRtaW4iLCJmaXJlc3RhcnRlcl9jbGFpbSI6ImFsbG93In0.invalidsignature"
	jwtRandomBearerValue    = "firestarter-random-bearer-token"
)

type jwtBaselineSnapshot struct {
	statusCode int
	authHeader string
	setCookies []string
	body       string
}

type jwtProbeOutcome struct {
	name       string
	token      string
	statusCode int
	body       string
	err        error
}

func (m *JWTSecurityAudit) captureBaseline(ctx context.Context) jwtBaselineSnapshot {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return jwtBaselineSnapshot{}
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return jwtBaselineSnapshot{}
	}
	defer resp.Body.Close()

	respBody, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)

	return jwtBaselineSnapshot{
		statusCode: resp.StatusCode,
		authHeader: strings.ToLower(resp.Header.Get("WWW-Authenticate")),
		setCookies: resp.Header.Values("Set-Cookie"),
		body:       string(respBody),
	}
}

func isJWTLike(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	return true
}

func baselineUsesJWTSession(b jwtBaselineSnapshot) bool {
	if strings.Contains(b.authHeader, "bearer") {
		return true
	}
	for _, c := range b.setCookies {
		cookieValue := c
		if idx := strings.Index(cookieValue, ";"); idx >= 0 {
			cookieValue = cookieValue[:idx]
		}
		if eq := strings.Index(cookieValue, "="); eq >= 0 && eq < len(cookieValue)-1 {
			cookieValue = cookieValue[eq+1:]
		}
		if isJWTLike(strings.TrimSpace(cookieValue)) {
			return true
		}
	}
	return false
}

func (m *JWTSecurityAudit) probeNoToken(ctx context.Context) jwtProbeOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return jwtProbeOutcome{name: "no_token", err: err}
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return jwtProbeOutcome{name: "no_token", err: err}
	}
	defer resp.Body.Close()
	respBody, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	return jwtProbeOutcome{name: "no_token", statusCode: resp.StatusCode, body: strings.ToLower(string(respBody))}
}

func (m *JWTSecurityAudit) probeToken(ctx context.Context, name string, token string) jwtProbeOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return jwtProbeOutcome{name: name, token: token, err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.Client.Do(req)
	if err != nil {
		return jwtProbeOutcome{name: name, token: token, err: err}
	}
	defer resp.Body.Close()
	respBody, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)

	return jwtProbeOutcome{name: name, token: token, statusCode: resp.StatusCode, body: strings.ToLower(string(respBody))}
}

func isAuthAcceptedStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest && statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden
}

// tokenOutcomeIndicatesClaimBinding reports whether an accepted alg=none
// response shows authorization effects bound to the forged token's claims.
// Bare generic markers ("ok", "allow", "success") and empty bodies no longer
// count: acceptance must either echo an exact claim pair carried by the forged
// payload, or differ from a rejected control response while the control matches
// the baseline.
func tokenOutcomeIndicatesClaimBinding(outcome jwtProbeOutcome, controlOutcome *jwtProbeOutcome, baselineBody string) bool {
	if !isAuthAcceptedStatus(outcome.statusCode) {
		return false
	}
	if outcome.body == "" {
		return false
	}
	// Exact claim pairs from the forged alg=none payload (sub=firestarter_admin,
	// scope=admin). Generic words are deliberately excluded.
	if containsAnyToken(outcome.body, []string{"firestarter_admin", `"scope":"admin"`}) {
		return true
	}
	if controlOutcome == nil {
		return false
	}
	tier := EvaluateDifferentialEvidence(outcome.body, controlOutcome.body, baselineBody, baselineBody != "")
	return tier == EvidenceConfirmed
}

func (m *JWTSecurityAudit) Execute(ctx context.Context) ([]JWTSecurityAuditResult, error) {
	m.results = make([]JWTSecurityAuditResult, 0)

	baseline := m.captureBaseline(ctx)
	if !baselineUsesJWTSession(baseline) {
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Endpoint did not present JWT-based authentication artifacts, so alg=none attribution is inconclusive."),
		})
		return m.results, nil
	}

	if baseline.statusCode != http.StatusUnauthorized && baseline.statusCode != http.StatusForbidden {
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Endpoint baseline was not clearly auth-gated (401/403), so alg=none acceptance cannot be causally attributed."),
		})
		return m.results, nil
	}

	outcomes := make([]jwtProbeOutcome, 0, 2+len(jwtNonePayloads))
	outcomes = append(outcomes, m.probeNoToken(ctx))
	outcomes = append(outcomes, m.probeToken(ctx, "random_bearer", jwtRandomBearerValue))
	outcomes = append(outcomes, m.probeToken(ctx, "invalid_signed", jwtInvalidSignedPayload))
	for i, token := range jwtNonePayloads {
		outcomes = append(outcomes, m.probeToken(ctx, fmt.Sprintf("alg_none_%d", i+1), token))
	}

	nonNoneAccepted := false
	noneAccepted := false
	noneClaimBound := false
	failedProbes := make([]string, 0)

	// Control (non-none) outcomes are used to differentially judge whether an
	// accepted alg=none response shows claim-linked authorization effects.
	var randomOutcome, invalidOutcome *jwtProbeOutcome
	for i := range outcomes {
		switch outcomes[i].name {
		case "random_bearer":
			randomOutcome = &outcomes[i]
		case "invalid_signed":
			invalidOutcome = &outcomes[i]
		}
	}

	for i := range outcomes {
		outcome := outcomes[i]
		if outcome.err != nil {
			failedProbes = append(failedProbes, outcome.name)
			continue
		}
		if outcome.name == "no_token" {
			// The endpoint serving an authenticated-context response with no
			// token at all is part of the same bearer-bypass class.
			if isAuthAcceptedStatus(outcome.statusCode) {
				nonNoneAccepted = true
			}
			continue
		}
		if outcome.name == "random_bearer" || outcome.name == "invalid_signed" {
			if isAuthAcceptedStatus(outcome.statusCode) {
				nonNoneAccepted = true
			}
			continue
		}
		if strings.HasPrefix(outcome.name, "alg_none_") {
			if isAuthAcceptedStatus(outcome.statusCode) {
				noneAccepted = true
				control := randomOutcome
				if control == nil || control.err != nil {
					control = invalidOutcome
				}
				if control != nil && control.err == nil && tokenOutcomeIndicatesClaimBinding(outcome, control, baseline.body) {
					noneClaimBound = true
				}
			}
		}
	}

	switch {
	case noneAccepted && !nonNoneAccepted && noneClaimBound:
		summary := "Differential matrix rejected random/invalid JWT probes while accepting alg=none tokens with claim-linked authorization outcome changes."
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, summary),
		})
	case noneAccepted && !nonNoneAccepted && !noneClaimBound:
		summary := "alg=none tokens were accepted while non-none probes were rejected, but claim-linked authorization change was not reproduced."
		if len(failedProbes) > 0 {
			summary = fmt.Sprintf("Differential matrix incomplete: control probe(s) failed (%s); alg=none acceptance could not be differentially judged against a rejected control.", strings.Join(failedProbes, ", "))
		}
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, summary),
		})
	case noneAccepted && nonNoneAccepted:
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "Bearer bypass was observed for multiple token classes, so acceptance is not uniquely attributable to alg=none."),
		})
	default:
		detail := "Differential matrix showed no acceptance path specific to alg=none JWT tokens."
		if len(failedProbes) > 0 {
			detail = fmt.Sprintf("Differential matrix incomplete: %d probe(s) failed (%s); alg=none acceptance could not be confirmed or ruled out.", len(failedProbes), strings.Join(failedProbes, ", "))
		}
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, true),
			Detail: formatEvidenceDetail(EvidenceWeak, detail),
		})
	}

	if nonNoneAccepted {
		summary := "Endpoint accepts arbitrary bearer tokens: random and/or invalid-signed JWTs (or requests with no token) are accepted without verification."
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, summary),
		})
	}

	return m.results, nil
}

func init() {
	RegisterModule("jwt_security_audit", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting JWTSecurityAudit on: %s", target))

		tester := NewJWTSecurityAudit(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
