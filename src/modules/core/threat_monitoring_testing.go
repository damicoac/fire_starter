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
	if !m.checkIsAlive(ctx) {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "error",
			Detail: "Target is down or unreachable during baseline check",
		}), nil
	}

	// Aggressive Burst
	var wg sync.WaitGroup
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
				if err == nil {
					resp.Body.Close()
				}
			}
		}(i)
	}
	wg.Wait()

	// Verification
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return results, err
	}

	resp, err := m.Client.Do(req)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return append(results, ThreatMonitoringResult{
				Target: m.Target,
				Status: "error",
				Detail: "Verification request timed out (context deadline exceeded).",
			}), nil
		}
		// Connection dropped or timeout, indicating potential blocking
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "secure",
			Detail: "Active blocking detected. Connection failed after aggressive burst.",
		}), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: "secure",
			Detail: "Active monitoring detected. Server returned 403 or 429 after aggressive burst.",
		}), nil
	}

	return append(results, ThreatMonitoringResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: "No active threat monitoring detected. Server allowed aggressive burst without blocking.",
	}), nil
}

func (m *ThreatMonitoringTesting) checkIsAlive(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return false
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
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
