package modules

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// HttpVerbTamperingResult holds the result of the HttpVerbTampering module execution.
type HttpVerbTamperingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HttpVerbTampering executes the http_verb_tampering security technique.
type HttpVerbTampering struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []HttpVerbTamperingResult
	client     *http.Client
}

// NewHttpVerbTampering creates a new instance.
func NewHttpVerbTampering(target string) *HttpVerbTampering {
	return &HttpVerbTampering{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *HttpVerbTampering) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var verbsToTest = []string{
	"PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "TRACK", "PATCH",
}

func (m *HttpVerbTampering) Execute(ctx context.Context) ([]HttpVerbTamperingResult, error) {
	m.results = make([]HttpVerbTamperingResult, 0)

	jobs := make(chan string, len(verbsToTest))
	for _, v := range verbsToTest {
		jobs <- v
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for verb := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testVerb(ctx, verb)
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

func (m *HttpVerbTampering) testVerb(ctx context.Context, verb string) {
	req, err := http.NewRequestWithContext(ctx, verb, m.Target, nil)
	if err != nil {
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		m.mu.Lock()
		m.results = append(m.results, HttpVerbTamperingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Endpoint accepted non-standard verb: " + verb + " (HTTP 200 OK)",
		})
		m.mu.Unlock()
	}
}
