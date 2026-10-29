package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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

	// per-run probe bookkeeping (guarded by m.Mu)
	attempted    bool
	probeErr     error
	lastNon2xx   int
	missingFound bool
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
	m.Mu.Lock()
	m.attempted = false
	m.probeErr = nil
	m.lastNon2xx = 0
	m.missingFound = false
	m.Mu.Unlock()

	// Per-run dedup map so repeat scans re-report findings instead of being
	// silently swallowed by process-global state.
	seen := make(map[string]bool)

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
					m.testHeaders(ctx, ep, seen)
				}
			}
		}()
	}

	wg.Wait()

	// Never end silently-empty: summarize the run outcome.
	m.Mu.Lock()
	if len(m.results) == 0 && m.attempted && ctx.Err() == nil {
		switch {
		case m.probeErr != nil:
			m.results = append(m.results, SecurityHeadersResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: fmt.Sprintf("Security headers could not be evaluated: %v", m.probeErr),
			})
		case m.lastNon2xx != 0:
			m.results = append(m.results, SecurityHeadersResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: fmt.Sprintf("Endpoint returned HTTP %d; security headers were not evaluated.", m.lastNon2xx),
			})
		case !m.missingFound:
			m.results = append(m.results, SecurityHeadersResult{
				Target: m.Target,
				Status: "secure",
				Detail: "All checked security headers present",
			})
		}
	}
	res := make([]SecurityHeadersResult, len(m.results))
	copy(res, m.results)
	m.Mu.Unlock()
	return res, nil
}

func (m *SecurityHeaders) testHeaders(ctx context.Context, endpoint string, seen map[string]bool) {
	testURL := m.Target + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	m.Mu.Lock()
	m.attempted = true
	m.Mu.Unlock()

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		if m.probeErr == nil {
			m.probeErr = err
		}
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	// Only judge 2xx responses: error pages and redirects do not carry the
	// security posture of the actual application surface.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		m.Mu.Lock()
		m.lastNon2xx = resp.StatusCode
		m.Mu.Unlock()
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

	if len(missing) == 0 {
		return
	}

	detailStr := fmt.Sprintf("Missing headers: %s", strings.Join(missing, ", "))
	dedupKey := testURL + "|" + detailStr

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if seen[dedupKey] {
		return
	}
	seen[dedupKey] = true
	m.missingFound = true
	m.RecordPoC(req, nil, fmt.Sprintf("Missing Security Headers at: %s", testURL))
	m.results = append(m.results, SecurityHeadersResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: detailStr,
	})
}

func init() {
	RegisterModule("security_headers_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
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
