package core

import (
	"context"
	"fmt"
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
	BaseModule
	Target  string
	results []CorsMisconfigurationAnalysisResult
}

// NewCorsMisconfigurationAnalysis creates a new instance.
func NewCorsMisconfigurationAnalysis(target string) *CorsMisconfigurationAnalysis {
	return &CorsMisconfigurationAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *CorsMisconfigurationAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *CorsMisconfigurationAnalysis) Execute(ctx context.Context) ([]CorsMisconfigurationAnalysisResult, error) {
	m.results = make([]CorsMisconfigurationAnalysisResult, 0)

	originsToTest := []string{
		"https://evil.com",
		"http://evil.com",
		"null",
	}

	host := ExtractHostname(m.Target)
	if host != "" {
		originsToTest = append(originsToTest, "https://subdomain."+host+".evil.com")
	} else {
		originsToTest = append(originsToTest, "https://subdomain.target.com.evil.com")
	}

	jobs := make(chan string, len(originsToTest))
	for _, o := range originsToTest {
		jobs <- o
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
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
		if len(m.results) == 0 {
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "safe",
				Detail: "No CORS misconfiguration detected. All tested malicious origins were rejected.",
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		if len(m.results) == 0 {
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "safe",
				Detail: "No CORS misconfiguration detected. All tested malicious origins were rejected.",
			})
		}
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

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	// Vulnerable if it reflects our malicious origin and allows credentials
	if allowOrigin == origin || allowOrigin == "*" {
		if allowCreds == "true" {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "CORS misconfiguration: Allows Origin '"+origin+"' with Credentials")
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CORS misconfiguration: Allows Origin '" + origin + "' with Credentials",
			})
			m.Mu.Unlock()
		} else if allowOrigin == "null" {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "CORS misconfiguration: Allows 'null' Origin")
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CORS misconfiguration: Allows 'null' Origin",
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("cors_misconfiguration_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CorsMisconfigurationAnalysis on: %s", target))

		tester := NewCorsMisconfigurationAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
