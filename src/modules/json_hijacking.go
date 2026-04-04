package modules

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []JsonHijackingTestResult
	client     *http.Client
}

// NewJsonHijackingTest creates a new instance.
func NewJsonHijackingTest(target string) *JsonHijackingTest {
	return &JsonHijackingTest{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *JsonHijackingTest) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *JsonHijackingTest) Execute(ctx context.Context) ([]JsonHijackingTestResult, error) {
	m.results = make([]JsonHijackingTestResult, 0)

	// For JSON Hijacking, we look for APIs that return top-level arrays AND don't require custom headers or unguessable CSRF tokens.
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return m.results, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return m.results, err
	}

	bodyStr := strings.TrimSpace(string(bodyBytes))

	// If it returns a top-level array, it might be vulnerable to JSON Hijacking
	if strings.HasPrefix(bodyStr, "[") && strings.HasSuffix(bodyStr, "]") {
		m.results = append(m.results, JsonHijackingTestResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential JSON Hijacking vulnerability: Endpoint returns a top-level JSON array without requiring specific CSRF protection headers.",
		})
	}

	return m.results, nil
}
