// src/modules/threat_monitoring_testing.go
package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ThreatMonitoringResult represents the outcome of a threat monitoring test.
type ThreatMonitoringResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ThreatMonitoringTesting encapsulates the state and logic for testing if a target has active threat monitoring.
type ThreatMonitoringTesting struct {
	BaseModule
	Target     string
	burstCount int
}

// NewThreatMonitoringTesting creates a new instance of ThreatMonitoringTesting with the specified target URL.
func NewThreatMonitoringTesting(target string) *ThreatMonitoringTesting {
	return &ThreatMonitoringTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target:     EnsureHTTPPrefix(target),
		burstCount: 50,
	}
}

func (m *ThreatMonitoringTesting) SetBurstCount(count int) {
	m.burstCount = count
}

// Execute runs the threat monitoring test against the configured target.
// It sends a burst of potentially malicious payloads to see if the server actively blocks or rate-limits the connection.
func (m *ThreatMonitoringTesting) Execute(ctx context.Context) ([]ThreatMonitoringResult, error) {
	results := make([]ThreatMonitoringResult, 0)

	// Baseline
	isAlive, baselineStatus := m.getBaseline(ctx)
	if !isAlive {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "error",
			Detail: "Target is down or unreachable during baseline check",
		}), nil
	}

	// Aggressive Burst
	var (
		wg                 sync.WaitGroup
		mu                 sync.Mutex
		blockedCount       int
		errorCount         int
	)
	sem := make(chan struct{}, 50) // Max 50 concurrent requests
	payloads := []string{
		"1' OR '1'='1",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
	}

	for i := 0; i < m.burstCount; i++ {
		wg.Add(1)
		sem <- struct{}{} // Acquire token
		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }() // Release token

			payload := payloads[index%len(payloads)]
			q := url.Values{}
			q.Add("q", payload)
			targetURL := m.Target + "/?" + q.Encode()

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err == nil {
				resp, err := m.Client.Do(req)
				if err != nil {
					mu.Lock()
					errorCount++
					mu.Unlock()
				} else {
					// Check if status is indicative of a block and DIFFERENT from baseline
					if resp.StatusCode != baselineStatus && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusNotAcceptable || resp.StatusCode == http.StatusUnauthorized) {
						mu.Lock()
						blockedCount++
						mu.Unlock()
					}
					resp.Body.Close()
				}
			}
		}(i)
	}
	wg.Wait()

	// Consider it active monitoring if > 10% of requests explicitly blocked,
	// or if > 20% resulted in errors (connection drops) which could indicate IP ban.
	explicitBlockThreshold := m.burstCount / 10
	if explicitBlockThreshold < 1 {
		explicitBlockThreshold = 1
	}
	errorBlockThreshold := m.burstCount / 5
	if errorBlockThreshold < 1 {
		errorBlockThreshold = 1
	}

	blockedDuringBurst := blockedCount >= explicitBlockThreshold || errorCount >= errorBlockThreshold

	// Verification
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return results, err
	}

	resp, err := m.Client.Do(req)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			// A timeout might just be an overloaded server, not necessarily a block.
			if !blockedDuringBurst && errorCount < errorBlockThreshold {
				return append(results, ThreatMonitoringResult{
					Target: m.Target,
					Status: "vulnerable",
					Detail: "No active threat monitoring detected. Server timed out but no explicit blocks were observed.",
				}), nil
			}
			return append(results, ThreatMonitoringResult{
				Target: m.Target,
				Status: "error",
				Detail: "Verification request timed out (context deadline exceeded).",
			}), nil
		}
		
		// Connection dropped or timeout, indicating potential blocking
		// Only consider it a block if we had some errors during the burst
		if errorCount >= explicitBlockThreshold {
			return append(results, ThreatMonitoringResult{
				Target: m.Target,
				Status: "secure",
				Detail: "Active blocking detected. Connection failed after aggressive burst.",
			}), nil
		}
		
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "No active threat monitoring detected. Server allowed aggressive burst without explicit blocking.",
		}), nil
	}
	defer resp.Body.Close()

	if blockedDuringBurst || (resp.StatusCode != baselineStatus && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests)) {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "secure",
			Detail: "Active monitoring detected. Server actively blocked requests during or after aggressive burst.",
		}), nil
	}

	return append(results, ThreatMonitoringResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: "No active threat monitoring detected. Server allowed aggressive burst without blocking.",
	}), nil
}

func (m *ThreatMonitoringTesting) getBaseline(ctx context.Context) (bool, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return false, 0
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500, resp.StatusCode
}

func init() {
	RegisterModule("threat_monitoring_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting ThreatMonitoringTesting on: %s", target))

		tester := NewThreatMonitoringTesting(target)
		tester.SetBurstCount(PayloadInt(payload, "burst_count", 50))

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
