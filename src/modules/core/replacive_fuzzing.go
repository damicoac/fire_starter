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

// ReplaciveFuzzingResult holds the result of the ReplaciveFuzzing module execution.
type ReplaciveFuzzingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ReplaciveFuzzing executes the replacive_fuzzing security technique.
type ReplaciveFuzzing struct {
	BaseModule
	Target  string
	results []ReplaciveFuzzingResult
}

// NewReplaciveFuzzing creates a new instance.
func NewReplaciveFuzzing(target string) *ReplaciveFuzzing {
	return &ReplaciveFuzzing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *ReplaciveFuzzing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var fuzzingStrings = []string{
	"'", "\"", "''", "\"\"", ";", "--", "/*", "*/",
	"%", "_", "[]", "{}", "()", "\\", "/",
	"\x00", "\x0a", "\x0d", "\n", "\r",
	"1/0", "9999999999999999999999999999999999",
	"-1", "-2147483648", "2147483647",
	"../../../../../../../../../../etc/passwd",
	"<script>alert(1)</script>",
}

func (m *ReplaciveFuzzing) Execute(ctx context.Context) ([]ReplaciveFuzzingResult, error) {
	m.results = make([]ReplaciveFuzzingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	// Benign baseline: without it, a transient 500 blip or a pre-broken endpoint that
	// 500s universally would be reported as payload-caused crashes.
	baselineReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, ReplaciveFuzzingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline request could not be built: %v", err)),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	baselineResp, err := m.Client.Do(baselineReq)
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, ReplaciveFuzzingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline request failed; fuzzing results cannot be attributed: %v", err)),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	baselineStatus := baselineResp.StatusCode
	baselineResp.Body.Close()
	// A healthy baseline (2xx/3xx/4xx) makes a payload-time 5xx attributable to the
	// payload; a 5xx baseline means the endpoint is already broken.
	baselineHealthy := baselineStatus >= http.StatusOK && baselineStatus < http.StatusInternalServerError

	jobs := make(chan string, len(fuzzingStrings))
	for _, p := range fuzzingStrings {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, parsedURL, payload, baselineHealthy)
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
			m.Mu.Lock()
			detail := "No fuzzing payload triggered a payload-specific server error or connection crash."
			if !baselineHealthy {
				detail = "Baseline endpoint already returns a server error; payload-specific 5xx judging was disabled."
			}
			m.results = append(m.results, ReplaciveFuzzingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, detail),
			})
			m.Mu.Unlock()
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

// replaciveIsCrashIndicator reports whether a transport error looks like the target process
// or worker crashed mid-response (connection reset, broken pipe, truncated body).
// Timeouts are deliberately excluded: they indicate slowness or overload, not a crash.
func replaciveIsCrashIndicator(err error) bool {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "unexpected eof")
}

func (m *ReplaciveFuzzing) testPayload(ctx context.Context, u *url.URL, payload string, baselineHealthy bool) {
	query := u.Query()
	testURL := *u

	if len(query) > 0 {
		for key := range query {
			query.Set(key, payload)
		}
		testURL.RawQuery = query.Encode()
	} else {
		testURL.Path = testURL.Path + "/" + payload
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		// A connection reset / truncated response under the payload is crash evidence
		// (the baseline request succeeded, so the transport itself was healthy).
		if replaciveIsCrashIndicator(err) {
			m.Mu.Lock()
			detail := "Fuzzing payload caused a connection-level crash (connection reset/truncated response): " + payload
			m.RecordPoC(req, nil, detail)
			m.results = append(m.results, ReplaciveFuzzingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, false),
				Detail: detail,
			})
			m.Mu.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	// 5xx evidence requires a healthy baseline so a pre-broken endpoint or transient
	// blip is not reported as payload-caused; 502/504 additionally indicate a killed
	// backend worker rather than application input validation.
	switch {
	case resp.StatusCode == http.StatusInternalServerError && baselineHealthy:
		m.Mu.Lock()
		detail := "Fuzzing payload caused HTTP 500 Internal Server Error (baseline responded normally): " + payload
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, ReplaciveFuzzingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	case (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout) && baselineHealthy:
		// A single 502/504 can be a transient upstream blip; re-issue the
		// payload once and require the failure to reproduce before calling it
		// a confirmed worker crash.
		reproducible := false
		retryReq, retryErr := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if retryErr == nil {
			retryResp, doErr := m.Client.Do(retryReq)
			if doErr == nil {
				if retryResp.StatusCode == http.StatusBadGateway || retryResp.StatusCode == http.StatusGatewayTimeout {
					reproducible = true
				}
				retryResp.Body.Close()
			} else if replaciveIsCrashIndicator(doErr) {
				// The connection died on the retry: the backend failed again
				// under the same payload, which is reproduction evidence.
				reproducible = true
			}
		}
		m.Mu.Lock()
		var detail string
		var evidence EvidenceTier
		if reproducible {
			evidence = EvidenceConfirmed
			detail = fmt.Sprintf("Fuzzing payload caused HTTP %d from the backend on two consecutive requests, indicating a worker crash: %s", resp.StatusCode, payload)
		} else {
			evidence = EvidenceStrong
			detail = fmt.Sprintf("Fuzzing payload caused a single HTTP %d from the backend (not reproduced on re-issue); reported as inconclusive: %s", resp.StatusCode, payload)
		}
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, ReplaciveFuzzingResult{
			Target: m.Target,
			Status: statusFromEvidence(evidence, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("replacive_fuzzing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting ReplaciveFuzzing on: %s", target))

		tester := NewReplaciveFuzzing(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
