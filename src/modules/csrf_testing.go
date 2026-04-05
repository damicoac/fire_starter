package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []CSRFTestingResult
	client     *http.Client
}

// NewCSRFTesting creates a new instance.
func NewCSRFTesting(target string) *CSRFTesting {
	return &CSRFTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *CSRFTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
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

	for i := 0; i < m.maxThreads; i++ {
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

	resp, err := m.client.Do(req)
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
		m.mu.Lock()
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential CSRF vulnerability: POST accepted without CSRF token at " + targetURL,
		})
		m.mu.Unlock()
	}
}
