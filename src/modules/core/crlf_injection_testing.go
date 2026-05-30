package core

import (
	"context"
	"fmt"
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
	BaseModule
	Target  string
	results []CrlfInjectionTestingResult
}

// NewCrlfInjectionTesting creates a new instance of CrlfInjectionTesting.
func NewCrlfInjectionTesting(target string) *CrlfInjectionTesting {
	// We want to test redirect/header injection without following redirects automatically
	client := NewHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	}

	return &CrlfInjectionTesting{
		BaseModule: BaseModule{
			Client:     client,
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *CrlfInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	for i := 0; i < m.MaxThreads; i++ {
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

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if our injected cookie made it to the response headers
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "crlf" && cookie.Value == "injected" {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "CRLF Injection successful. Injected header detected.")
			m.results = append(m.results, CrlfInjectionTestingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CRLF Injection successful. Injected header detected.",
			})
			m.Mu.Unlock()
			return
		}
	}
}

func init() {
	RegisterModule("crlf_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CrlfInjectionTesting on: %s", target))

		tester := NewCrlfInjectionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
