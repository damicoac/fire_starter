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

	baselineReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, nil
	}

	baselineStatus := 0
	baselineResp, err := m.Client.Do(baselineReq)
	if err == nil {
		baselineStatus = baselineResp.StatusCode
		baselineResp.Body.Close()
	}

	numRequests := 50
	jobs := make(chan int, numRequests)
	for i := 0; i < numRequests; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	var got429 bool
	var gotRetryAfter bool
	var gotAuthChallenge bool
	var successCount int
	var completedRequests int
	var firstHalfSuccess int
	var secondHalfSuccess int
	var lastReq *http.Request

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					req, reqErr := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
					if reqErr != nil {
						continue
					}

					m.Mu.Lock()
					lastReq = req
					m.Mu.Unlock()

					resp, doErr := m.Client.Do(req)
					if doErr != nil {
						continue
					}

					m.Mu.Lock()
					completedRequests++
					if resp.StatusCode == http.StatusTooManyRequests {
						got429 = true
					}
					if resp.Header.Get("Retry-After") != "" {
						gotRetryAfter = true
					}
					if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
						gotAuthChallenge = true
					}
					if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
						successCount++
						if idx < numRequests/2 {
							firstHalfSuccess++
						} else {
							secondHalfSuccess++
						}
					}
					m.Mu.Unlock()

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
		m.Mu.Lock()
		throttle429 := got429
		retryAfterObserved := gotRetryAfter
		authObserved := gotAuthChallenge
		requestsDone := completedRequests
		totalSuccess := successCount
		firstSuccess := firstHalfSuccess
		secondSuccess := secondHalfSuccess
		m.Mu.Unlock()

		successRate := safeRatio(totalSuccess, requestsDone)
		firstHalfRate := safeRatio(firstSuccess, numRequests/2)
		secondHalfRate := safeRatio(secondSuccess, numRequests/2)
		hasBurstDegradation := firstHalfRate-secondHalfRate > 0.25

		switch {
		case baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden || authObserved:
			m.RecordPoC(lastReq, nil, "Endpoint remained behind authentication controls during burst probing.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: "No explicit throttling signal detected, but endpoint was access-controlled (401/403).",
			})
		case requestsDone < numRequests/2 || successRate < 0.4:
			m.RecordPoC(lastReq, nil, "Burst probing produced unstable responses; throttling result inconclusive.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: "Burst probing produced insufficient stable responses for reliable rate-limit classification.",
			})
		case throttle429 && (retryAfterObserved || hasBurstDegradation):
			m.RecordPoC(lastReq, nil, "Rate limiting detected via HTTP 429 with corroborating throttling behavior.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "secure",
				Detail: "Rate limiting detected: HTTP 429 observed with corroborating throttling indicators.",
			})
		case throttle429 && !retryAfterObserved && !hasBurstDegradation:
			m.RecordPoC(lastReq, nil, "HTTP 429 responses observed without additional throttling signals; classification inconclusive.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: "HTTP 429 observed, but corroborating throttling indicators were weak or absent.",
			})
		default:
			m.RecordPoC(lastReq, nil, "No throttling indicators detected after burst probing against a reachable endpoint.")
			m.results = append(m.results, RateLimitProbingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "No throttling indicators detected after 50 rapid requests against an accessible endpoint.",
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
