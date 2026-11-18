package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// XpathInjectionTestingResult holds the result of the XpathInjectionTesting module execution.
type XpathInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// XpathInjectionTesting executes the xpath_injection_testing security technique.
type XpathInjectionTesting struct {
	BaseModule
	Target  string
	results []XpathInjectionTestingResult
}

// NewXpathInjectionTesting creates a new instance.
func NewXpathInjectionTesting(target string) *XpathInjectionTesting {
	return &XpathInjectionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *XpathInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var xpathPayloads = []string{
	"' or '1'='1",
	"\" or \"1\"=\"1",
	"'] | //user/* [ '1'='1",
}

// fetchBaseline performs the payload-free request whose body serves as the
// differential baseline: an error marker already present without any payload
// is not injection evidence.
func (m *XpathInjectionTesting) fetchBaseline(ctx context.Context, u *url.URL) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", false
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return "", false
	}
	return string(bodyBytes), true
}

// containsXPathErrorMarker reports whether a body carries the XPath error
// signature conjunction.
func containsXPathErrorMarker(bodyLower string) bool {
	return strings.Contains(bodyLower, "xpath") &&
		(strings.Contains(bodyLower, "syntax error") || strings.Contains(bodyLower, "invalid expression"))
}

func (m *XpathInjectionTesting) Execute(ctx context.Context) ([]XpathInjectionTestingResult, error) {
	m.results = make([]XpathInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	baselineBody, baselineOK := m.fetchBaseline(ctx, parsedURL)
	if !baselineOK {
		m.Mu.Lock()
		m.results = append(m.results, XpathInjectionTestingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline request failed (transport or read error); XPath injection could not be assessed.",
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	jobs := make(chan string, len(xpathPayloads))
	for _, p := range xpathPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup
	attempted, failed := 0, 0

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.Mu.Lock()
					attempted++
					m.Mu.Unlock()
					if !m.testPayload(ctx, parsedURL, payload, baselineBody) {
						m.Mu.Lock()
						failed++
						m.Mu.Unlock()
					}
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
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}

	if attempted > 0 && failed >= attempted {
		m.Mu.Lock()
		m.results = append(m.results, XpathInjectionTestingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("All %d probes failed (request or transport errors); XPath injection could not be assessed.", attempted),
		})
		m.Mu.Unlock()
	}
	return m.results, nil
}

// testPayload sends one payload probe and judges it against the payload-free
// baseline. It returns false when the probe itself failed (request build,
// transport, or body read error).
func (m *XpathInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload, baselineBody string) bool {
	query := u.Query()
	hasParams := len(query) > 0

	testURL := *u
	if hasParams {
		for key, vals := range query {
			for i, val := range vals {
				query[key][i] = val + payload
			}
		}
		testURL.RawQuery = query.Encode()
	} else {
		query.Add("q", payload)
		query.Add("search", payload)
		testURL.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return false
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return false
	}

	bodyStr := strings.ToLower(string(bodyBytes))
	baseLower := strings.ToLower(baselineBody)

	// Mirror sql_injection_testing.go: the error marker counts only when the
	// payload-free baseline body does not already carry it (a broken query or
	// a generic error page is not injection evidence).
	if containsXPathErrorMarker(bodyStr) && !containsXPathErrorMarker(baseLower) {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "XPath Injection detected via error signature with payload: "+payload)
		m.results = append(m.results, XpathInjectionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "XPath Injection detected via error signature with payload: " + payload,
		})
		m.Mu.Unlock()
	}
	return true
}

func init() {
	RegisterModule("xpath_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting XpathInjectionTesting on: %s", target))

		tester := NewXpathInjectionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
