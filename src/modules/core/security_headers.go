package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	securityHeadersSeen sync.Map
)

type SecurityHeadersResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type SecurityHeaders struct {
	BaseModule
	Target  string
	results []SecurityHeadersResult
}

func NewSecurityHeaders(target string) *SecurityHeaders {
	return &SecurityHeaders{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *SecurityHeaders) Execute(ctx context.Context) ([]SecurityHeadersResult, error) {
	m.results = make([]SecurityHeadersResult, 0)

	endpoints := []string{"/"}

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
					m.testHeaders(ctx, ep)
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *SecurityHeaders) testHeaders(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return
	}

	missing := []string{}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html")

	if resp.Header.Get("Content-Security-Policy") == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if isHTML && resp.Header.Get("X-Frame-Options") == "" {
		missing = append(missing, "X-Frame-Options (Clickjacking)")
	}

	if len(missing) > 0 {
		detailStr := fmt.Sprintf("Missing headers: %s", strings.Join(missing, ", "))
		
		dedupKey := testURL + "|" + detailStr
		if _, loaded := securityHeadersSeen.LoadOrStore(dedupKey, true); loaded {
			return
		}

		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("Missing Security Headers at: %s", testURL))
		m.results = append(m.results, SecurityHeadersResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: detailStr,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("security_headers_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting SecurityHeaders on: %s", target))
		tester := NewSecurityHeaders(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
