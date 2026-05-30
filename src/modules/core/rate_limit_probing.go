package core

import (
	"context"
	"fmt"
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
	BaseModule
	Target  string
	results []RateLimitProbingResult
}

// NewRateLimitProbing creates a new instance.
func NewRateLimitProbing(target string) *RateLimitProbing {
	return &RateLimitProbing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *RateLimitProbing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	for i := 0; i < m.MaxThreads; i++ {
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

					resp, err := m.Client.Do(req)
					if err != nil {
						continue
					}

					if resp.StatusCode == http.StatusTooManyRequests {
						m.Mu.Lock()
						got429 = true
						m.Mu.Unlock()
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
			m.RecordPoC(nil, nil, "No rate limiting (HTTP 429) detected after 50 rapid requests.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "No rate limiting (HTTP 429) detected after 50 rapid requests.",
			})
		} else {
			m.RecordPoC(nil, nil, "Rate limiting is properly enforced (HTTP 429 received).")
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

func init() {
	RegisterModule("rate_limit_probing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting RateLimitProbing on: %s", target))

		tester := NewRateLimitProbing(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
