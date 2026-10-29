package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HttpVerbTamperingResult holds the result of the HttpVerbTampering module execution.
type HttpVerbTamperingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ResponseBaseline struct {
	StatusCode int
	Length     int64
}

// HttpVerbTampering executes the http_verb_tampering security technique.
type HttpVerbTampering struct {
	BaseModule
	Target          string
	results         []HttpVerbTamperingResult
	baselineGet     ResponseBaseline
	baselineBogus   ResponseBaseline
	baselineGetOK   bool
	baselineBogusOK bool
	allowMutation   bool
	probeErrCount   int
	probeCount      int
}

// NewHttpVerbTampering creates a new instance.
func NewHttpVerbTampering(target string) *HttpVerbTampering {
	return &HttpVerbTampering{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *HttpVerbTampering) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// SetAllowMutating opts in to state-changing PUT/DELETE/PATCH probes. Mutation
// probes are skipped entirely unless explicitly enabled.
func (m *HttpVerbTampering) SetAllowMutating(allow bool) {
	m.allowMutation = allow
}

var verbsToTest = []string{
	"OPTIONS", "HEAD", "CONNECT", "PUT", "DELETE", "TRACE", "TRACK", "PATCH",
	"GeT", "POst", "pUT", // case variations
	"BOGUSVERB", // arbitrary verb
}

// isMutationVerb reports whether the verb can change server-side state.
func isMutationVerb(verb string) bool {
	switch verb {
	case "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

// isRoutinelyUnauthenticated reports whether servers normally allow the verb
// without authentication (CORS preflight, cacheable HEAD probes).
func isRoutinelyUnauthenticated(verb string) bool {
	switch verb {
	case "OPTIONS", "HEAD":
		return true
	}
	return false
}

func (m *HttpVerbTampering) runBaseline(ctx context.Context) {
	m.baselineGet, m.baselineGetOK = m.fetchBaseline(ctx, "GET")
	m.baselineBogus, m.baselineBogusOK = m.fetchBaseline(ctx, "JEAN_BOGUS_VERB")
}

func (m *HttpVerbTampering) fetchBaseline(ctx context.Context, verb string) (ResponseBaseline, bool) {
	req, err := http.NewRequestWithContext(ctx, verb, m.Target, nil)
	if err != nil {
		return ResponseBaseline{}, false
	}

	if cookies := m.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	for k, v := range m.OriginalHeaders {
		req.Header[k] = v
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return ResponseBaseline{}, false
	}
	defer resp.Body.Close()

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return ResponseBaseline{}, false
	}
	return ResponseBaseline{
		StatusCode: resp.StatusCode,
		Length:     int64(len(body)),
	}, true
}

func (m *HttpVerbTampering) Execute(ctx context.Context) ([]HttpVerbTamperingResult, error) {
	m.results = make([]HttpVerbTamperingResult, 0)
	m.Mu.Lock()
	m.probeErrCount = 0
	m.probeCount = 0
	m.Mu.Unlock()

	m.runBaseline(ctx)

	// Without usable baselines the discriminators below are meaningless
	// (zero-value baselines make every response look divergent).
	if !m.baselineGetOK || !m.baselineBogusOK {
		m.Mu.Lock()
		m.results = append(m.results, HttpVerbTamperingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline request failed; HTTP verb tampering could not be evaluated.",
		})
		res := make([]HttpVerbTamperingResult, len(m.results))
		copy(res, m.results)
		m.Mu.Unlock()
		return res, nil
	}

	jobs := make(chan string, len(verbsToTest))
	for _, v := range verbsToTest {
		if isMutationVerb(strings.ToUpper(v)) && !m.allowMutation {
			continue
		}
		jobs <- v
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for verb := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testVerb(ctx, verb)
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
		m.summarize()
		res := make([]HttpVerbTamperingResult, len(m.results))
		copy(res, m.results)
		m.Mu.Unlock()
		return res, nil
	case <-ctx.Done():
		<-done
		m.Mu.Lock()
		m.summarize()
		res := make([]HttpVerbTamperingResult, len(m.results))
		copy(res, m.results)
		m.Mu.Unlock()
		return res, ctx.Err()
	}
}

// summarize appends a closing row so a clean or partially-failed run is never
// silently empty. Callers must hold m.Mu.
func (m *HttpVerbTampering) summarize() {
	if len(m.results) > 0 {
		return
	}
	if m.probeErrCount > 0 {
		m.results = append(m.results, HttpVerbTamperingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("%d of %d verb probes failed; verb handling could not be fully evaluated.", m.probeErrCount, m.probeCount),
		})
		return
	}
	m.results = append(m.results, HttpVerbTamperingResult{
		Target: m.Target,
		Status: "secure",
		Detail: "All tested verbs were rejected or handled consistently with the GET baseline.",
	})
}

// resourceChanged re-fetches the GET baseline and reports whether the resource
// representation or status diverged, providing positive evidence that a
// state-changing verb actually modified the resource.
func (m *HttpVerbTampering) resourceChanged(ctx context.Context) bool {
	after, ok := m.fetchBaseline(ctx, "GET")
	if !ok {
		return false
	}
	return after.StatusCode != m.baselineGet.StatusCode || after.Length != m.baselineGet.Length
}

func (m *HttpVerbTampering) testVerb(ctx context.Context, verb string) {
	verbUpper := strings.ToUpper(verb)

	// State-changing verbs carry a JSON body with an inert marker.
	isStateChanging := isMutationVerb(verbUpper)
	var bodyReader io.Reader
	var bodyBytes []byte
	if isStateChanging {
		bodyBytes = []byte(`{"tamper_test":"123"}`)
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, verb, m.Target, bodyReader)
	if err != nil {
		return
	}

	if isStateChanging {
		req.Header.Set("Content-Type", "application/json")
	}

	if cookies := m.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	for k, v := range m.OriginalHeaders {
		req.Header[k] = v
	}

	m.Mu.Lock()
	m.probeCount++
	m.Mu.Unlock()

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeErrCount++
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	respBody, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.probeErrCount++
		m.Mu.Unlock()
		return
	}
	respLength := int64(len(respBody))

	// Analysis
	isVulnerable := false
	detail := ""

	// 1. Authentication/Authorization Bypass.
	// GET requires auth (401/403) but this verb returns 2xx with content.
	// Verbs that are routinely served unauthenticated (OPTIONS preflight,
	// HEAD) are excluded to avoid flagging normal API behavior, and the
	// response must diverge from the catch-all bogus-verb baseline in BOTH
	// status and length with a non-empty body.
	if !isRoutinelyUnauthenticated(verbUpper) &&
		(m.baselineGet.StatusCode == http.StatusUnauthorized || m.baselineGet.StatusCode == http.StatusForbidden) &&
		(resp.StatusCode >= 200 && resp.StatusCode < 300) &&
		resp.StatusCode != m.baselineBogus.StatusCode &&
		respLength != m.baselineBogus.Length &&
		respLength > 0 {
		isVulnerable = true
		detail = fmt.Sprintf("Authentication bypass detected. GET returned %d, but %s returned %d with content.", m.baselineGet.StatusCode, verb, resp.StatusCode)
	}

	// 2. Successful Execution of State-Changing Verbs.
	// Acceptance alone is not evidence: require positive acceptance evidence —
	// either the inert marker echoed back, or the resource actually changed.
	if !isVulnerable && isStateChanging && (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		if strings.Contains(string(respBody), "tamper_test") || m.resourceChanged(ctx) {
			isVulnerable = true
			detail = fmt.Sprintf("State-changing verb %s accepted and confirmed: server echoed probe marker or resource state changed.", verb)
		}
	}

	// 3. WAF / Filter Bypass (Case Sensitivity)
	if !isVulnerable && verb != verbUpper && (resp.StatusCode >= 200 && resp.StatusCode < 300) && respLength > 0 {
		if m.baselineGet.StatusCode != resp.StatusCode {
			// This indicates the mixed-case verb bypassed whatever was blocking the standard GET
			isVulnerable = true
			detail = fmt.Sprintf("Possible filter bypass. Mixed-case verb %s returned %d (GET was %d).", verb, resp.StatusCode, m.baselineGet.StatusCode)
		}
	}

	if isVulnerable {
		m.Mu.Lock()
		m.RecordPoC(req, bodyBytes, detail)
		m.results = append(m.results, HttpVerbTamperingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("http_verb_tampering", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting HttpVerbTampering on: %s", target))

		tester := NewHttpVerbTampering(target)
		allowMutation := false
		switch strings.ToLower(PayloadString(payload, "allow_mutating", "")) {
		case "true", "1", "yes", "on":
			allowMutation = true
		}
		tester.SetAllowMutating(allowMutation)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
