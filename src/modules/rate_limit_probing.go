package modules

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// RateLimitProbingResult holds the result of the RateLimitProbing module execution.
type RateLimitProbingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// RateLimitProbing executes the rate_limit_probing security technique.
type RateLimitProbing struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []RateLimitProbingResult
	client     *http.Client
}

// NewRateLimitProbing creates a new instance.
func NewRateLimitProbing(target string) *RateLimitProbing {
	return &RateLimitProbing{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 10,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *RateLimitProbing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *RateLimitProbing) Execute(ctx context.Context) ([]RateLimitProbingResult, error) {
	m.results = make([]RateLimitProbingResult, 0)

	// Send 50 requests rapidly to see if we get a 429 Too Many Requests
	numRequests := 50
	jobs := make(chan int, numRequests)
	for i := 0; i < numRequests; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	var got429 bool

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
					if err != nil {
						continue
					}

					resp, err := m.client.Do(req)
					if err != nil {
						continue
					}

					if resp.StatusCode == http.StatusTooManyRequests {
						m.mu.Lock()
						got429 = true
						m.mu.Unlock()
					}
					resp.Body.Close()
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
		if !got429 {
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "No rate limiting (HTTP 429) detected after 50 rapid requests.",
			})
		} else {
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "secure",
				Detail: "Rate limiting is properly enforced (HTTP 429 received).",
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}
