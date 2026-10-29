// src/modules/threat_monitoring_testing.go
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
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
	if count < 1 {
		count = 1
	}
	m.burstCount = count
}

func (m *ThreatMonitoringTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// Execute runs the threat monitoring test against the configured target.
// It sends a burst of potentially malicious payloads to see if the server actively blocks or rate-limits the connection.
func (m *ThreatMonitoringTesting) Execute(ctx context.Context) ([]ThreatMonitoringResult, error) {
	results := make([]ThreatMonitoringResult, 0)

	// Baseline: a successful pre-burst baseline is required before burst behavior can
	// be attributed to active blocking rather than plain overload.
	baselineStatus, err := m.getBaseline(ctx)
	if err != nil {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Target is down or unreachable during baseline check: %v", err)),
		}), nil
	}
	if baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline endpoint is auth-gated (401/403), so unauthenticated threat-monitoring probing is inconclusive."),
		}), nil
	}
	if baselineStatus >= http.StatusInternalServerError {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline returned HTTP %d; burst behavior cannot be attributed to active blocking.", baselineStatus)),
		}), nil
	}

	// Aggressive Burst
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		blockedCount int
		refusedCount int
		timeoutCount int
		readFailures int
	)
	// Derive burst concurrency from the configured thread count instead of a
	// hardcoded 50, so a small MaxThreads cannot self-overload the target.
	concurrency := m.MaxThreads
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	payloads := []string{
		"1' OR '1'='1",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
	}

	baseURL, err := url.Parse(m.Target)
	if err != nil {
		return results, err
	}

	for i := range m.burstCount {
		wg.Add(1)
		sem <- struct{}{} // Acquire token
		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }() // Release token

			payload := payloads[index%len(payloads)]
			// Merge into the existing query instead of blindly appending "/?" so a
			// target that already carries a query string does not get a double "?".
			u := *baseURL
			q := u.Query()
			q.Set("q", payload)
			u.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if err == nil {
				resp, err := m.Client.Do(req)
				if err != nil {
					mu.Lock()
					// Distinguish refusal/reset (possible IP-ban style blocking) from
					// timeouts (plain overload); only refusals may attribute blocks.
					if threatMonitorIsRefusalErr(err) {
						refusedCount++
					} else if threatMonitorIsTimeoutErr(err) {
						timeoutCount++
					}
					mu.Unlock()
					return
				}
				body, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
				resp.Body.Close()
				if readErr != nil {
					// The body could not be read, so the WAF-marker judge is
					// disabled for this response; count it as a failed probe
					// instead of silently treating it as marker-free.
					body = nil
					mu.Lock()
					readFailures++
					mu.Unlock()
				}
				isBlockStatus := resp.StatusCode == http.StatusUnauthorized ||
					resp.StatusCode == http.StatusForbidden ||
					resp.StatusCode == http.StatusNotAcceptable ||
					resp.StatusCode == http.StatusTooManyRequests
				// A burst response counts as blocked when it is a block-status differing
				// from baseline, or a block-status carrying WAF markers even when it
				// matches an auth-gated baseline status.
				if isBlockStatus && (resp.StatusCode != baselineStatus || threatMonitorContainsWAFMarker(string(body))) {
					mu.Lock()
					blockedCount++
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()

	// Consider it active monitoring if > 10% of requests explicitly blocked.
	explicitBlockThreshold := m.burstCount / 10
	if explicitBlockThreshold < 1 {
		explicitBlockThreshold = 1
	}
	errorBlockThreshold := m.burstCount / 5
	if errorBlockThreshold < 1 {
		errorBlockThreshold = 1
	}

	blockedDuringBurst := blockedCount >= explicitBlockThreshold
	// Refused/reset connections during the burst can indicate IP-ban style blocking.
	refusedDuringBurst := refusedCount >= errorBlockThreshold

	// Verification, retried once so a single flaky failure cannot decide the outcome.
	verifyStatus := 0
	var verifyErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
		if err != nil {
			return results, err
		}
		resp, err := m.Client.Do(req)
		if err != nil {
			verifyErr = err
			continue
		}
		verifyStatus = resp.StatusCode
		resp.Body.Close()
		verifyErr = nil
		break
	}

	if verifyErr != nil {
		// Only refused/reset-style failures after the burst support an active-block
		// attribution; timeouts alone are indistinguishable from overload.
		if refusedDuringBurst && threatMonitorIsRefusalErr(verifyErr) {
			return append(results, ThreatMonitoringResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, true),
				Detail: formatEvidenceDetail(EvidenceConfirmed, "Active blocking detected: connections were refused or reset during and after the aggressive burst."),
			}), nil
		}
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Verification request failed (%v; burst refusals: %d, burst timeouts: %d); cannot distinguish server overload from active blocking.", verifyErr, refusedCount, timeoutCount)),
		}), nil
	}

	if blockedDuringBurst || (verifyStatus != baselineStatus && (verifyStatus == http.StatusForbidden || verifyStatus == http.StatusNotAcceptable || verifyStatus == http.StatusTooManyRequests || verifyStatus == http.StatusUnauthorized)) {
		return append(results, ThreatMonitoringResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, true),
			Detail: formatEvidenceDetail(EvidenceConfirmed, "Active monitoring detected. Server actively blocked requests during or after aggressive burst."),
		}), nil
	}

	cleanDetail := "No active threat monitoring detected. Server allowed aggressive burst without blocking."
	if readFailures > 0 {
		cleanDetail += fmt.Sprintf(" (%d burst response(s) could not be read; WAF-marker check was skipped for them)", readFailures)
	}
	return append(results, ThreatMonitoringResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceConfirmed, false),
		Detail: formatEvidenceDetail(EvidenceConfirmed, cleanDetail),
	}), nil
}

func (m *ThreatMonitoringTesting) getBaseline(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// threatMonitorWAFMarkers are body markers that identify an edge/WAF block page.
var threatMonitorWAFMarkers = []string{
	"cloudflare", "cloudfront", "incapsula", "sucuri", "akamai",
	"request blocked", "access denied", "captcha", "web application firewall",
}

func threatMonitorContainsWAFMarker(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range threatMonitorWAFMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// threatMonitorIsRefusalErr reports refused/RST-style connection failures, the signature
// of IP-ban style blocking rather than plain overload.
func threatMonitorIsRefusalErr(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe")
}

// threatMonitorIsTimeoutErr reports timeout/deadline-style failures, which indicate
// slowness or overload rather than active blocking.
func threatMonitorIsTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
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
