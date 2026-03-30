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

// ServerSideTemplateInjectionSstiResult holds the result of the ServerSideTemplateInjectionSsti module execution.
type ServerSideTemplateInjectionSstiResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ServerSideTemplateInjectionSsti executes the server_side_template_injection_ssti security technique.
type ServerSideTemplateInjectionSsti struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []ServerSideTemplateInjectionSstiResult
	client     *http.Client
}

// NewServerSideTemplateInjectionSsti creates a new instance.
func NewServerSideTemplateInjectionSsti(target string) *ServerSideTemplateInjectionSsti {
	return &ServerSideTemplateInjectionSsti{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *ServerSideTemplateInjectionSsti) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

type sstiPayload struct {
	payload  string
	expected string
}

var sstiPayloads = []sstiPayload{
	{"{{7*7}}", "49"},
	{"${7*7}", "49"},
	{"<%= 7*7 %>", "49"},
	{"#{7*7}", "49"},
	{"*{7*7}", "49"},
}

func (m *ServerSideTemplateInjectionSsti) Execute(ctx context.Context) ([]ServerSideTemplateInjectionSstiResult, error) {
	m.results = make([]ServerSideTemplateInjectionSstiResult, 0)
	
	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan sstiPayload, len(sstiPayloads))
	for _, p := range sstiPayloads {
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

func (m *ServerSideTemplateInjectionSsti) testPayload(ctx context.Context, u *url.URL, sp sstiPayload) {
	query := u.Query()
	hasParams := len(query) > 0
	
	testURL := *u
	if hasParams {
		for key, vals := range query {
			for i, val := range vals {
				query[key][i] = val + sp.payload
			}
		}
		testURL.RawQuery = query.Encode()
	} else {
		query.Add("name", sp.payload)
		query.Add("q", sp.payload)
		query.Add("template", sp.payload)
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

	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, sp.expected) {
		// Prevent false positives if "49" was already on the page without execution
		// E.g., if we injected {{7*7}} and the output shows exactly "{{7*7}}", it failed.
		// If it shows "49" but not "{{7*7}}", it succeeded.
		if !strings.Contains(bodyStr, sp.payload) {
			m.mu.Lock()
			m.results = append(m.results, ServerSideTemplateInjectionSstiResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "SSTI execution successful with payload: " + sp.payload,
			})
			m.mu.Unlock()
		}
	}
}
