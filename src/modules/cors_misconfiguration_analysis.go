package modules

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CorsMisconfigurationAnalysisResult holds the result of the CorsMisconfigurationAnalysis module execution.
type CorsMisconfigurationAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CorsMisconfigurationAnalysis executes the cors_misconfiguration_analysis security technique.
type CorsMisconfigurationAnalysis struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []CorsMisconfigurationAnalysisResult
	client     *http.Client
}

// NewCorsMisconfigurationAnalysis creates a new instance.
func NewCorsMisconfigurationAnalysis(target string) *CorsMisconfigurationAnalysis {
	return &CorsMisconfigurationAnalysis{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *CorsMisconfigurationAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var corsOrigins = []string{
	"https://evil.com",
	"http://evil.com",
	"null",
	"https://subdomain.target.com.evil.com", // Prefix bypass attempt
}

func (m *CorsMisconfigurationAnalysis) Execute(ctx context.Context) ([]CorsMisconfigurationAnalysisResult, error) {
	m.results = make([]CorsMisconfigurationAnalysisResult, 0)

	jobs := make(chan string, len(corsOrigins))
	for _, o := range corsOrigins {
		jobs <- o
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for origin := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testOrigin(ctx, origin)
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

func (m *CorsMisconfigurationAnalysis) testOrigin(ctx context.Context, origin string) {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", m.Target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	// Vulnerable if it reflects our malicious origin and allows credentials
	if allowOrigin == origin || allowOrigin == "*" {
		if allowCreds == "true" {
			m.mu.Lock()
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CORS misconfiguration: Allows Origin '" + origin + "' with Credentials",
			})
			m.mu.Unlock()
		} else if allowOrigin == "null" {
			m.mu.Lock()
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CORS misconfiguration: Allows 'null' Origin",
			})
			m.mu.Unlock()
		}
	}
}
