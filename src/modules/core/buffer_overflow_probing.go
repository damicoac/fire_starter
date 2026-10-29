package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BufferOverflowProbingResult holds the result of the BufferOverflowProbing module execution.
type BufferOverflowProbingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BufferOverflowProbing executes the buffer_overflow_probing security technique.
type BufferOverflowProbing struct {
	BaseModule
	Target  string
	results []BufferOverflowProbingResult
	// Transport/build failures and observed crash-style errors.
	probeErrs []string
	// Crashes reported as connection resets / mid-response EOF, distinct from
	// clean HTTP responses.
	crashErrs []string
}

// NewBufferOverflowProbing creates a new instance.
func NewBufferOverflowProbing(target string) *BufferOverflowProbing {
	return &BufferOverflowProbing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *BufferOverflowProbing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// bufferOverflowPayloadLengths keeps the graded lengths used for
// length-dependent behavior checks.
var bufferOverflowPayloadLengths = []int{1000, 10000, 50000}

func (m *BufferOverflowProbing) Execute(ctx context.Context) ([]BufferOverflowProbingResult, error) {
	m.Mu.Lock()
	m.results = make([]BufferOverflowProbingResult, 0)
	m.probeErrs = nil
	m.crashErrs = nil
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	// Benign baseline with the UNPOLLUTED original query: judges rely on it to
	// distinguish pre-broken endpoints from payload-specific failures.
	baselineStatus, baselineBody, baselineErr := m.fetchWithQuery(ctx, parsedURL, parsedURL.RawQuery)
	if baselineErr != nil {
		m.Mu.Lock()
		m.results = append(m.results, BufferOverflowProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline request failed: %v", baselineErr)),
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	jobs := make(chan string, len(bufferOverflowPayloadLengths))
	for _, l := range bufferOverflowPayloadLengths {
		jobs <- strings.Repeat("A", l)
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, parsedURL, payload, baselineStatus, baselineBody)
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
		if len(m.results) == 0 {
			switch {
			case len(m.crashErrs) > 0:
				m.results = append(m.results, BufferOverflowProbingResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceStrong, false),
					Detail: formatEvidenceDetail(EvidenceStrong, fmt.Sprintf("Connection failure under oversized input (possible crash): %s", m.crashErrs[0])),
				})
			case len(m.probeErrs) > 0:
				m.results = append(m.results, BufferOverflowProbingResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceWeak, false),
					Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All probes failed; first error: %s", m.probeErrs[0])),
				})
			}
		}
		m.Mu.Unlock()
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *BufferOverflowProbing) recordProbeError(err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.probeErrs) < 8 {
		m.probeErrs = append(m.probeErrs, err.Error())
	}
}

func (m *BufferOverflowProbing) recordCrashError(err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.crashErrs) < 8 {
		m.crashErrs = append(m.crashErrs, err.Error())
	}
}

// fetchWithQuery issues a GET with the given raw query and returns
// status/body. Connection resets and mid-response EOFs are surfaced as crash
// evidence instead of being silently discarded.
func (m *BufferOverflowProbing) fetchWithQuery(ctx context.Context, u *url.URL, rawQuery string) (int, string, error) {
	testURL := *u
	testURL.RawQuery = rawQuery

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return 0, "", fmt.Errorf("failed to build request: %w", err)
	}

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		if bufferOverflowIsCrashStyleError(err) {
			m.recordCrashError(fmt.Errorf("crash-style failure on %s: %w", testURL.RawQuery, err))
		}
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _, readErr := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		// A reset mid-response is also crash evidence.
		if bufferOverflowIsCrashStyleError(readErr) {
			m.recordCrashError(fmt.Errorf("crash-style failure mid-response on %s: %w", testURL.RawQuery, readErr))
		}
		return resp.StatusCode, "", fmt.Errorf("failed to read response body: %w", readErr)
	}

	return resp.StatusCode, string(bodyBytes), nil
}

// bufferOverflowIsCrashStyleError reports whether a transport/read error looks like the
// server died mid-request (connection reset, unexpected EOF) rather than a
// routine network failure.
func bufferOverflowIsCrashStyleError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "EOF")
}

// testPayload probes ONE parameter per request, keeping every other parameter
// at its original value so authentication/CSRF params survive and failures are
// attributable to the single mutated parameter.
func (m *BufferOverflowProbing) testPayload(ctx context.Context, u *url.URL, payload string, baselineStatus int, baselineBody string) {
	query := u.Query()
	if len(query) == 0 {
		query.Add("input", payload)
		testURL := *u
		testURL.RawQuery = query.Encode()
		m.probeOneParam(ctx, &testURL, "input", payload, baselineStatus, baselineBody)
		return
	}

	for key := range query {
		probeQuery := url.Values{}
		for k, v := range query {
			if k == key {
				continue
			}
			probeQuery[k] = v
		}
		probeQuery[key] = []string{payload}

		testURL := *u
		testURL.RawQuery = probeQuery.Encode()
		m.probeOneParam(ctx, &testURL, key, payload, baselineStatus, baselineBody)
	}
}

// probeOneParam judges a single oversized-parameter response against the
// unpolluted baseline: vulnerable only when the oversized request fails with a
// 500 while the baseline succeeds, or when behavior degrades with length.
func (m *BufferOverflowProbing) probeOneParam(ctx context.Context, testURL *url.URL, key string, payload string, baselineStatus int, baselineBody string) {
	status, body, err := m.fetchWithQuery(ctx, testURL, testURL.RawQuery)
	if err != nil {
		// Crash-style errors are already recorded; plain transport errors here.
		if !bufferOverflowIsCrashStyleError(err) {
			m.recordProbeError(fmt.Errorf("probe param %s: %w", key, err))
		}
		return
	}

	// Only a 500 that the unpolluted baseline does NOT produce is payload-
	// attributable: a pre-broken endpoint 500ing universally is not evidence.
	if status != http.StatusInternalServerError || baselineStatus == http.StatusInternalServerError {
		return
	}

	// Length-graded behavior: when multiple lengths were probed for this
	// parameter, require that the failure scales with payload length. We
	// approximate by re-probing with a small benign-ish value: if a short
	// value on the same parameter also 500s, the failure is input-validation,
	// not overflow.
	shortQuery := url.Values{}
	for k, v := range testURL.Query() {
		if k == key {
			continue
		}
		shortQuery[k] = v
	}
	shortQuery[key] = []string{"A"}
	shortStatus, _, shortErr := m.fetchWithQuery(ctx, testURL, shortQuery.Encode())
	if shortErr == nil && shortStatus == http.StatusInternalServerError {
		// Short input also fails: generic validation failure, not overflow.
		return
	}

	// A 500 whose body is byte-identical to a baseline 500 body is a static
	// error page, not a crash caused by this payload.
	if baselineStatus == status && baselineBody == body {
		return
	}

	detail := fmt.Sprintf("Large input caused HTTP 500 on parameter '%s' while the unpolluted baseline succeeded (Length: %d)", key, len(payload))
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	m.Mu.Lock()
	m.RecordPoC(req, nil, detail)
	m.results = append(m.results, BufferOverflowProbingResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceConfirmed, false),
		Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
	})
	m.Mu.Unlock()
}

func init() {
	RegisterModule("buffer_overflow_probing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting BufferOverflowProbing on: %s", target))

		tester := NewBufferOverflowProbing(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
