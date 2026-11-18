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

	// We will attempt to send 20 requests in synchronized volleys to see if responses differ.
	numRequests := 20

	// fireVolley sends count identical state-changing requests in synchronized
	// volleys and returns the observed status-code counts (excluding uniform
	// noise statuses) plus the number of probes that failed with build or
	// transport errors.
	fireVolley := func(count int) (map[int]int, int) {
		responses := make(map[int]int) // status code counts
		var respMu sync.Mutex
		probeErrors := 0

		for start := 0; start < count; start += m.MaxThreads {
			end := start + m.MaxThreads
			if end > count {
				end = count
			}
			volleySize := end - start

			// Barrier re-armed per volley: every request in the volley waits until all
			// volley members are ready, so the whole volley fires as close together as
			// possible instead of only the first MaxThreads jobs synchronizing.
			var ready sync.WaitGroup
			ready.Add(volleySize)
			release := make(chan struct{})

			var wg sync.WaitGroup
			for i := start; i < end; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ready.Done()
					<-release

					select {
					case <-ctx.Done():
						return
					default:
						req, err := http.NewRequestWithContext(ctx, "POST", m.Target, nil)
						if err != nil {
							respMu.Lock()
							probeErrors++
							respMu.Unlock()
							return
						}
						// Dummy form to simulate a state-changing action
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

						resp, err := m.Client.Do(req)
						if err != nil {
							respMu.Lock()
							probeErrors++
							respMu.Unlock()
							return
						}

						respMu.Lock()
						// Exclude statuses that are uniform noise under concurrency (rate
						// limiting, overload, gateway failures) so they cannot manufacture a
						// fabricated mix; 500 is excluded uniformly with 502/503/504.
						if resp.StatusCode != 429 && resp.StatusCode != 500 && resp.StatusCode != 502 && resp.StatusCode != 503 && resp.StatusCode != 504 {
							responses[resp.StatusCode]++
						}
						respMu.Unlock()
						resp.Body.Close()
					}
				}()
			}

			ready.Wait()
			close(release)
			wg.Wait()
		}
		return responses, probeErrors
	}

	// classify sums the status counts into state-change evidence buckets.
	// A race manifests as inconsistent enforcement for identical state-changing
	// requests: multiple 2xx acceptances alongside 4xx rejections. E.g. a coupon
	// code accepted 3 times (200) and rejected 17 times (400) when it should only
	// be accepted once. Mixed 2xx/3xx or 2xx/404 outcomes carry no state-change
	// evidence, and uniform outcomes (including all-success) are inconclusive here
	// because this module cannot inspect server-side state.
	classify := func(responses map[int]int) (successCount, rejectionCount int) {
		for status, count := range responses {
			if status >= 200 && status < 300 {
				successCount += count
				continue
			}
			if status >= 400 && status < 500 && status != http.StatusNotFound && status != http.StatusTooManyRequests {
				rejectionCount += count
			}
		}
		return
	}

	responses, probeErrors := fireVolley(numRequests)
	successCount, rejectionCount := classify(responses)

	m.Mu.Lock()
	defer m.Mu.Unlock()

	switch {
	case len(responses) == 0:
		// Every probe errored (or was cancelled before any response): report
		// the failure instead of letting an all-errored volley look clean.
		detail := "No race-condition probe produced a classifiable response; race condition could not be assessed."
		if probeErrors > 0 {
			detail = fmt.Sprintf("All %d race-condition probes failed with build/transport errors; race condition could not be assessed.", probeErrors)
		}
		m.results = append(m.results, RaceConditionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: detail,
		})
	case successCount > 1 && rejectionCount > 0:
		// A single mixed 2xx/4xx volley is not sufficient race evidence: the
		// mix must reproduce on a second identical volley before it is
		// reported as a confirmed race condition.
		secondResponses, _ := fireVolley(numRequests)
		secondSuccess, secondRejection := classify(secondResponses)
		if secondSuccess > 1 && secondRejection > 0 {
			detail := fmt.Sprintf("Race condition: two consecutive concurrent volleys yielded inconsistent enforcement (first: %v, second: %v).", responses, secondResponses)
			m.results = append(m.results, RaceConditionTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, false),
				Detail: detail,
			})
		} else {
			detail := fmt.Sprintf("Mixed enforcement (%v) was not reproduced on a second volley (mix: %v); race condition unconfirmed.", responses, secondResponses)
			m.results = append(m.results, RaceConditionTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: detail,
			})
		}
	default:
		detail := fmt.Sprintf("No race-condition differential observed from concurrent requests (status mix: %v).", responses)
		if probeErrors > 0 {
			detail += fmt.Sprintf(" %d probe(s) failed with build/transport errors.", probeErrors)
		}
		m.results = append(m.results, RaceConditionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: detail,
		})
	}

	if err := ctx.Err(); err != nil {
		return m.results, err
	}
	return m.results, nil
}

func init() {
	RegisterModule("race_condition_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
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
