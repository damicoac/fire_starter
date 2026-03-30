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

// CrossSiteScriptingInjectionResult holds the result of the CrossSiteScriptingInjection module execution.
type CrossSiteScriptingInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CrossSiteScriptingInjection executes the cross_site_scripting_injection security technique.
type CrossSiteScriptingInjection struct {
	Target     string
	Cookies    string
	maxThreads int
	mu         sync.Mutex
	results    []CrossSiteScriptingInjectionResult
	client     *http.Client
}

// NewCrossSiteScriptingInjection creates a new instance.
func NewCrossSiteScriptingInjection(target string) *CrossSiteScriptingInjection {
	return &CrossSiteScriptingInjection{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *CrossSiteScriptingInjection) SetCookies(cookies string) {
	m.Cookies = cookies
}

func (m *CrossSiteScriptingInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var xssPayloads = []string{
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"'-alert(1)-'",
}

func (m *CrossSiteScriptingInjection) Execute(ctx context.Context) ([]CrossSiteScriptingInjectionResult, error) {
	m.results = make([]CrossSiteScriptingInjectionResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(xssPayloads))
	for _, p := range xssPayloads {
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

func (m *CrossSiteScriptingInjection) testPayload(ctx context.Context, u *url.URL, payload string) {
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

	if m.Cookies != "" {
		req.Header.Set("Cookie", m.Cookies)
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

	// Check if our payload is reflected back unescaped
	if strings.Contains(bodyStr, payload) {
		m.mu.Lock()
		m.results = append(m.results, CrossSiteScriptingInjectionResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential reflected XSS found. Payload reflected unescaped: " + payload,
		})
		m.mu.Unlock()
	}
}
