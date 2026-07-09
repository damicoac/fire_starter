package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWTSecurityAuditResult holds the result of the JWTSecurityAudit module execution.
type JWTSecurityAuditResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// JWTSecurityAudit executes the jwt_security_audit security technique.
type JWTSecurityAudit struct {
	BaseModule
	Target  string
	results []JWTSecurityAuditResult
}

// NewJWTSecurityAudit creates a new instance.
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
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
	"eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
	"eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
}

const (
	jwtInvalidSignedPayload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.invalidsignature"
	jwtRandomBearerValue   = "firestarter-random-bearer-token"
)

type jwtBaselineSnapshot struct {
	statusCode int
	authHeader string
	setCookies []string
}

type jwtProbeOutcome struct {
	token      string
	statusCode int
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

	baseline := jwtBaselineSnapshot{
		statusCode: resp.StatusCode,
		authHeader: strings.ToLower(resp.Header.Get("WWW-Authenticate")),
		setCookies: resp.Header.Values("Set-Cookie"),
	}
	return baseline
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

func (m *JWTSecurityAudit) probeToken(ctx context.Context, token string) jwtProbeOutcome {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return jwtProbeOutcome{token: token, err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.Client.Do(req)
	if err != nil {
		return jwtProbeOutcome{token: token, err: err}
	}
	defer resp.Body.Close()

	return jwtProbeOutcome{token: token, statusCode: resp.StatusCode}
}

func isAuthAcceptedStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest && statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden
}

func (m *JWTSecurityAudit) Execute(ctx context.Context) ([]JWTSecurityAuditResult, error) {
	m.results = make([]JWTSecurityAuditResult, 0)

	baseline := m.captureBaseline(ctx)
	if !baselineUsesJWTSession(baseline) {
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Endpoint did not present JWT-based authentication artifacts, so alg=none verification is inconclusive.",
		})
		return m.results, nil
	}

	if baseline.statusCode != http.StatusUnauthorized && baseline.statusCode != http.StatusForbidden {
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline endpoint response was not auth-gated (401/403), so alg=none acceptance cannot be attributed safely.",
		})
		return m.results, nil
	}

	probeTokens := []string{jwtInvalidSignedPayload, jwtRandomBearerValue}
	probeTokens = append(probeTokens, jwtNonePayloads...)

	jobs := make(chan string, len(probeTokens))
	for _, token := range probeTokens {
		jobs <- token
	}
	close(jobs)

	outcomes := make([]jwtProbeOutcome, 0, len(probeTokens))
	var outcomesMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for token := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					outcome := m.probeToken(ctx, token)
					outcomesMu.Lock()
					outcomes = append(outcomes, outcome)
					outcomesMu.Unlock()
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		genericBypass := false
		noneAccepted := false
		for _, outcome := range outcomes {
			if outcome.err != nil {
				continue
			}
			if outcome.token == jwtInvalidSignedPayload || outcome.token == jwtRandomBearerValue {
				if isAuthAcceptedStatus(outcome.statusCode) {
					genericBypass = true
				}
				continue
			}
			if isAuthAcceptedStatus(outcome.statusCode) {
				noneAccepted = true
			}
		}

		switch {
		case noneAccepted && !genericBypass:
			m.RecordPoC(nil, nil, "Server accepted forged JWT token using alg=none while rejecting non-none bearer probes")
			m.results = append(m.results, JWTSecurityAuditResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Server accepted alg=none JWT while rejecting invalid signed/random bearer tokens.",
			})
		case noneAccepted && genericBypass:
			m.results = append(m.results, JWTSecurityAuditResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: "Bearer token bypass observed, but acceptance is not specific to alg=none.",
			})
		default:
			m.results = append(m.results, JWTSecurityAuditResult{
				Target: m.Target,
				Status: "secure",
				Detail: "No evidence that alg=none JWT tokens were accepted.",
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
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
