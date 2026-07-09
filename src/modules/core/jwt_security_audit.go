package core

import (
	"context"
	"fmt"
	"io"
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

	return jwtBaselineSnapshot{
		statusCode: resp.StatusCode,
		authHeader: strings.ToLower(resp.Header.Get("WWW-Authenticate")),
		setCookies: resp.Header.Values("Set-Cookie"),
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
	respBody, _ := io.ReadAll(resp.Body)
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
	respBody, _ := io.ReadAll(resp.Body)

	return jwtProbeOutcome{name: name, token: token, statusCode: resp.StatusCode, body: strings.ToLower(string(respBody))}
}

func isAuthAcceptedStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest && statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden
}

func tokenOutcomeIndicatesClaimBinding(outcome jwtProbeOutcome) bool {
	if !isAuthAcceptedStatus(outcome.statusCode) {
		return false
	}
	if outcome.body == "" {
		return true
	}
	return containsAnyToken(outcome.body, []string{"firestarter_admin", "scope", "admin", "role", "firestarter_claim", "allow", "ok", "success"})
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
	for _, outcome := range outcomes {
		if outcome.err != nil {
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
				if tokenOutcomeIndicatesClaimBinding(outcome) {
					noneClaimBound = true
				}
			}
		}
	}

	switch {
	case noneAccepted && !nonNoneAccepted && noneClaimBound:
		summary := "Differential matrix rejected random/invalid JWT probes while accepting alg=none tokens with claim-linked authorization outcome changes."
		m.RecordPoC(nil, nil, summary)
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, summary),
		})
	case noneAccepted && !nonNoneAccepted && !noneClaimBound:
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "alg=none tokens were accepted while non-none probes were rejected, but claim-linked authorization change was not reproduced."),
		})
	case noneAccepted && nonNoneAccepted:
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "Bearer bypass was observed for multiple token classes, so acceptance is not uniquely attributable to alg=none."),
		})
	default:
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, true),
			Detail: formatEvidenceDetail(EvidenceConfirmed, "Differential matrix showed no acceptance path specific to alg=none JWT tokens."),
		})
	}

	return m.results, nil
}

func init() {
	RegisterModule("jwt_security_audit", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
