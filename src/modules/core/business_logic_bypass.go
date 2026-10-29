package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type BusinessLogicBypassResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type BusinessLogicBypass struct {
	BaseModule
	Target  string
	results []BusinessLogicBypassResult

	// probe counters; guarded by Mu, read only after all workers finish.
	testedCount int
	deniedCount int
	probeErrors int
}

func NewBusinessLogicBypass(target string) *BusinessLogicBypass {
	return &BusinessLogicBypass{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

// businessLogicPositiveSignal reports whether a lowercase body carries an
// explicit success marker for the completed step.
func businessLogicPositiveSignal(bodyLower string) bool {
	return containsAnyToken(bodyLower, []string{"success", "confirmed", `"status":"ok"`})
}

// businessLogicNegativeSignal reports whether a lowercase body explicitly
// rejects or fails the request. Negatives are scoped to real rejection
// phrasing; a bare "error" substring wrongly rejects genuine success bodies
// such as {"status":"success","errors":[]}.
func businessLogicNegativeSignal(bodyLower string) bool {
	return containsAnyToken(bodyLower, []string{
		"not successful", "not confirmed", `"status":"error"`, "payment failed", "unauthorized",
	})
}

func (m *BusinessLogicBypass) Execute(ctx context.Context) ([]BusinessLogicBypassResult, error) {
	m.results = make([]BusinessLogicBypassResult, 0)
	m.testedCount = 0
	m.deniedCount = 0
	m.probeErrors = 0

	endpoints := []string{
		"/api/checkout/complete",
		"/checkout/complete",
		"/order/confirm",
		"/payment/process",
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testLogicBypass(ctx, ep)
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
		if len(m.results) == 0 {
			allDenied := m.testedCount > 0 && m.probeErrors == 0 && m.deniedCount >= m.testedCount
			var detail string
			switch {
			case m.probeErrors > 0:
				detail = fmt.Sprintf("%d of %d probes failed with transport errors; endpoints could not be assessed.", m.probeErrors, m.testedCount)
			case allDenied:
				detail = "All tested endpoints rejected the unauthenticated request."
			default:
				detail = "No business-logic bypass confirmed on the tested endpoints."
			}
			m.results = append(m.results, BusinessLogicBypassResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, allDenied),
				Detail: formatEvidenceDetail(EvidenceWeak, detail),
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *BusinessLogicBypass) testLogicBypass(ctx context.Context, endpoint string) {
	m.Mu.Lock()
	m.testedCount++
	m.Mu.Unlock()

	testURL := m.Target + endpoint

	// Baseline/control: plain GET of the same endpoint establishes what the
	// endpoint returns to a request that did not reach the state-changing
	// handler.
	getReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}
	getResp, err := m.Client.Do(getReq)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}
	getBody, err := ReadBoundedBody(getResp.Body, MaxResponseBodyBytes)
	getResp.Body.Close()
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}

	// Direct hit: POST without session or prior steps.
	req, err := http.NewRequestWithContext(ctx, "POST", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}
	bodyLower := strings.ToLower(string(bodyBytes))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		m.Mu.Lock()
		m.deniedCount++
		m.Mu.Unlock()
		return
	}

	// If the server doesn't reject us immediately with a 401/403 or logic error
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return
	}

	// Require an explicit success marker and no real rejection phrasing
	// before treating the response as a completed step.
	if businessLogicNegativeSignal(bodyLower) || !businessLogicPositiveSignal(bodyLower) {
		m.Mu.Lock()
		m.deniedCount++
		m.Mu.Unlock()
		return
	}

	// Differential gating: the success body must actually differ from the
	// endpoint's normal (control) GET response, so marketing copy or static
	// text containing "success" is not misread as a completed step.
	tier := EvaluateDifferentialEvidence(string(bodyBytes), string(getBody), string(getBody), true)
	if tier == EvidenceConfirmed {
		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("Potential Business Logic Bypass at: %s", testURL))
		m.results = append(m.results, BusinessLogicBypassResult{
			Target: m.Target,
			Status: statusFromEvidence(tier, false),
			Detail: formatEvidenceDetail(tier, fmt.Sprintf("Accessed final step endpoint %s successfully without context", testURL)),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("business_logic_bypass", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting BusinessLogicBypass on: %s", target))
		tester := NewBusinessLogicBypass(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
