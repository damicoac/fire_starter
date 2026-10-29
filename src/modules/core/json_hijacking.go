package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// JsonHijackingTestResult holds the result of the JsonHijackingTest module execution.
type JsonHijackingTestResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// JsonHijackingTest executes the json_hijacking_test security technique.
type JsonHijackingTest struct {
	BaseModule
	Target  string
	results []JsonHijackingTestResult
}

// NewJsonHijackingTest creates a new instance.
func NewJsonHijackingTest(target string) *JsonHijackingTest {
	return &JsonHijackingTest{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *JsonHijackingTest) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *JsonHijackingTest) Execute(ctx context.Context) ([]JsonHijackingTestResult, error) {
	m.results = make([]JsonHijackingTestResult, 0)

	// For JSON Hijacking, we look for APIs that return top-level arrays AND don't require custom headers or unguessable CSRF tokens.
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return m.results, err
	}
	defer resp.Body.Close()

	bodyBytes, truncated, err := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, JsonHijackingTestResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("Failed to read response body: %v", err),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	if truncated {
		m.Mu.Lock()
		m.results = append(m.results, JsonHijackingTestResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("Response body exceeded %d bytes and was truncated; JSON hijacking could not be assessed.", MaxResponseBodyBytes),
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	// Only a 2xx application/json response can represent the victim's
	// authenticated data; anything else (401 arrays, HTML pages, health
	// endpoints on other content types) cannot establish the hijacking
	// precondition.
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices ||
		!strings.Contains(contentType, "application/json") {
		return m.results, nil
	}

	var topLevels []json.RawMessage
	if err := json.Unmarshal(bodyBytes, &topLevels); err != nil {
		return m.results, nil
	}
	// `null` unmarshals into a nil slice and `[]` into an empty one: neither
	// exposes any records, so there is nothing to hijack.
	if len(topLevels) == 0 {
		return m.results, nil
	}

	// If it returns a top-level array, it might be vulnerable to JSON Hijacking
	m.RecordPoC(req, nil, "Potential JSON Hijacking vulnerability: Endpoint returns a top-level JSON array without requiring specific CSRF protection headers.")
	m.results = append(m.results, JsonHijackingTestResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: "Potential JSON Hijacking vulnerability: Endpoint returns a top-level JSON array without requiring specific CSRF protection headers.",
	})

	return m.results, nil
}

func init() {
	RegisterModule("json_hijacking_test", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting JsonHijackingTest on: %s", target))

		tester := NewJsonHijackingTest(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
