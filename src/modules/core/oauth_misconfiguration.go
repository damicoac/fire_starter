package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type OAuthMisconfigurationResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type OAuthMisconfiguration struct {
	BaseModule
	Target  string
	results []OAuthMisconfigurationResult
}

func NewOAuthMisconfiguration(target string) *OAuthMisconfiguration {
	return &OAuthMisconfiguration{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *OAuthMisconfiguration) Execute(ctx context.Context) ([]OAuthMisconfigurationResult, error) {
	m.results = make([]OAuthMisconfigurationResult, 0)

	endpoints := []string{
		"/oauth/authorize",
		"/oauth2/authorize",
		"/auth/authorize",
		"/login/oauth/authorize",
	}

	payloads := []string{
		"?response_type=token&client_id=test&redirect_uri=https://evil.com",
		"?response_type=code&client_id=test&redirect_uri=https://evil.com",
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
						m.testOAuth(ctx, ep, p)
					}
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *OAuthMisconfiguration) testOAuth(ctx context.Context, endpoint, payload string) {
	testURL := m.Target + endpoint + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	// We don't want to follow redirects automatically if we want to catch the Location header
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

	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(loc, "evil.com") {
		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("OAuth redirect_uri manipulation successful at: %s", testURL))
		m.results = append(m.results, OAuthMisconfigurationResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("OAuth redirect_uri manipulation allowed to %s", loc),
		})
		m.Mu.Unlock()
	} else if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "evil.com") {
			m.Mu.Lock()
			m.RecordPoC(req, nil, fmt.Sprintf("OAuth redirect_uri reflected in body at: %s", testURL))
			m.results = append(m.results, OAuthMisconfigurationResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("OAuth redirect_uri reflected, potential open redirect or XSS at %s", testURL),
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("oauth_misconfiguration_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting OAuthMisconfiguration on: %s", target))
		tester := NewOAuthMisconfiguration(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
