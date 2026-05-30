package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CSRFTestingResult holds the result of the CSRFTesting module execution.
type CSRFTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CSRFTesting executes the csrf_testing security technique.
type CSRFTesting struct {
	BaseModule
	Target  string
	results []CSRFTestingResult
}

// NewCSRFTesting creates a new instance.
func NewCSRFTesting(target string) *CSRFTesting {
	return &CSRFTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *CSRFTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *CSRFTesting) Execute(ctx context.Context) ([]CSRFTestingResult, error) {
	m.results = make([]CSRFTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	endpoints := []string{
		parsedURL.String(),
		strings.TrimRight(parsedURL.String(), "/") + "/api/settings",
		strings.TrimRight(parsedURL.String(), "/") + "/profile/update",
	}

	jobs := make(chan string, len(endpoints))
	for _, e := range endpoints {
		jobs <- e
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testEndpoint(ctx, targetURL)
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

func (m *CSRFTesting) testEndpoint(ctx context.Context, targetURL string) {
	// A simple test for CSRF is checking if state-changing requests (POST/PUT)
	// require anti-CSRF tokens. We send a bare POST without tokens.
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader("dummy=data"))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No CSRF header, no CSRF token in body

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// If the server accepts it (200 OK) without complaining about a missing token
	if resp.StatusCode == http.StatusOK &&
		!strings.Contains(strings.ToLower(bodyStr), "csrf") &&
		!strings.Contains(strings.ToLower(bodyStr), "token") {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Potential CSRF vulnerability: POST accepted without CSRF token at "+targetURL)
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential CSRF vulnerability: POST accepted without CSRF token at " + targetURL,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("csrf_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CSRFTesting on: %s", target))

		tester := NewCSRFTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
