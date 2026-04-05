package modules

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RaceConditionTestingResult holds the result of the RaceConditionTesting module execution.
type RaceConditionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// RaceConditionTesting executes the race_condition_testing security technique.
type RaceConditionTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []RaceConditionTestingResult
	client     *http.Client
}

// NewRaceConditionTesting creates a new instance.
func NewRaceConditionTesting(target string) *RaceConditionTesting {
	return &RaceConditionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 20, // Needs high concurrency for race conditions
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *RaceConditionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *RaceConditionTesting) Execute(ctx context.Context) ([]RaceConditionTestingResult, error) {
	m.results = make([]RaceConditionTestingResult, 0)

	// We will attempt to send 20 requests exactly at the same time to see if responses differ.
	numRequests := 20
	jobs := make(chan int, numRequests)
	for i := 0; i < numRequests; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	// Use a barrier to try and start them all at exactly the same time
	barrier := make(chan struct{})

	responses := make(map[int]int) // status code counts
	var respMu sync.Mutex

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				// Wait for everyone to get ready
				<-barrier

				select {
				case <-ctx.Done():
					return
				default:
					req, err := http.NewRequestWithContext(ctx, "POST", m.Target, nil)
					if err != nil {
						continue
					}
					// Dummy form to simulate a state-changing action
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

					resp, err := m.client.Do(req)
					if err != nil {
						continue
					}

					respMu.Lock()
					responses[resp.StatusCode]++
					respMu.Unlock()
					resp.Body.Close()
				}
			}
		}()
	}

	// Release the barrier
	close(barrier)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Analyze results. If we get a mix of 200s and 400s or 500s unexpectedly, it might indicate a race
		// E.g. a coupon code might be accepted 3 times (200) and rejected 17 times (400) when it should only be accepted once.
		if len(responses) > 1 {
			m.mu.Lock()
			m.results = append(m.results, RaceConditionTestingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Potential race condition: Multiple concurrent requests yielded mixed status codes: %v", responses),
			})
			m.mu.Unlock()
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}
