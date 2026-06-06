package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type OpenRedirectResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type OpenRedirect struct {
	BaseModule
	Target  string
	results []OpenRedirectResult
}

func NewOpenRedirect(target string) *OpenRedirect {
	return &OpenRedirect{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *OpenRedirect) Execute(ctx context.Context) ([]OpenRedirectResult, error) {
	m.results = make([]OpenRedirectResult, 0)

	endpoints := []string{
		"/login?next=",
		"/login?returnUrl=",
		"/logout?redirect=",
		"/redirect?url=",
		"/auth?url=",
	}

	payloads := []string{
		"http://evil.com",
		"//evil.com",
		"https://evil.com",
		"/%09/evil.com",
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					for _, p := range payloads {
						m.testRedirect(ctx, ep, p)
					}
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *OpenRedirect) testRedirect(ctx context.Context, endpoint, payload string) {
	testURL := m.Target + endpoint + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	// Disable automatic redirects
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: DefaultTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "evil.com") {
			m.Mu.Lock()
			m.RecordPoC(req, nil, fmt.Sprintf("Open Redirect at: %s", testURL))
			m.results = append(m.results, OpenRedirectResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Open redirect to %s via %s", loc, testURL),
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("open_redirect_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting OpenRedirect on: %s", target))
		tester := NewOpenRedirect(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
