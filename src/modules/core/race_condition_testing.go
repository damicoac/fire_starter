package core

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
	BaseModule
	Target  string
	results []RaceConditionTestingResult
}

// NewRaceConditionTesting creates a new instance.
func NewRaceConditionTesting(target string) *RaceConditionTesting {
	return &RaceConditionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target), // Needs high concurrency for race conditions
	}
}

func (m *RaceConditionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	for i := 0; i < m.MaxThreads; i++ {
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

					resp, err := m.Client.Do(req)
					if err != nil {
						continue
					}

					respMu.Lock()
					if resp.StatusCode != 429 && resp.StatusCode != 502 && resp.StatusCode != 503 && resp.StatusCode != 504 {
						responses[resp.StatusCode]++
					}
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
			m.Mu.Lock()
			m.RecordPoC(nil, nil, fmt.Sprintf("Potential race condition: Multiple concurrent requests yielded mixed status codes: %v", responses))
			m.results = append(m.results, RaceConditionTestingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Potential race condition: Multiple concurrent requests yielded mixed status codes: %v", responses),
			})
			m.Mu.Unlock()
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func init() {
	RegisterModule("race_condition_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting RaceConditionTesting on: %s", target))

		tester := NewRaceConditionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
