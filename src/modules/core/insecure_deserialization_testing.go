package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// InsecureDeserializationTestingResult holds the result of the InsecureDeserializationTesting module execution.
type InsecureDeserializationTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// InsecureDeserializationTesting executes the insecure_deserialization_testing security technique.
type InsecureDeserializationTesting struct {
	BaseModule
	Target  string
	results []InsecureDeserializationTestingResult

	attemptedProbes int64
	failedProbes    int64
}

// NewInsecureDeserializationTesting creates a new instance.
func NewInsecureDeserializationTesting(target string) *InsecureDeserializationTesting {
	return &InsecureDeserializationTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *InsecureDeserializationTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

type deserializationPayload struct {
	name    string
	payload string
	cookie  string
}

var desPayloads = []deserializationPayload{
	{"PHP Object", `O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}`, "session"},
	{"Java Magic Byte", "rO0ABXNyAApzZXJpYWxpemVk", "JSESSIONID"}, // Base64 of Java magic bytes AC ED 00 05
	{"Python Pickle", "gASVIQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJoaZGUhZRSlC4=", "session"},
}

// deserializationMarkers lists signatures for deserialization stack traces or
// errors. The Java set includes the exceptions a corrupt/garbled probe stream
// typically produces, not only the full readObject frame leak.
var deserializationMarkers = []string{
	"java.io.ObjectInputStream",
	"java.io.StreamCorruptedException",
	"java.io.InvalidClassException",
	"java.lang.ClassCastException",
	"unserialize(): Error",
	"_pickle.UnpicklingError",
}

func desBodyContainsMarker(body string) bool {
	return containsAnyToken(body, deserializationMarkers)
}

func (m *InsecureDeserializationTesting) Execute(ctx context.Context) ([]InsecureDeserializationTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]InsecureDeserializationTestingResult, 0)
	m.Mu.Unlock()

	jobs := make(chan deserializationPayload, len(desPayloads))
	for _, p := range desPayloads {
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
					m.testPayload(ctx, payload)
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
// every probe request failed, so an unreachable target is never reported as a
// clean scan.
func (m *InsecureDeserializationTesting) appendInconclusiveIfAllProbesFailed() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.results) > 0 {
		return
	}
	attempted := atomic.LoadInt64(&m.attemptedProbes)
	if attempted > 0 && atomic.LoadInt64(&m.failedProbes) >= attempted {
		m.results = append(m.results, InsecureDeserializationTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "All deserialization probes failed with transport errors or HTTP error responses; target reachability could not be established."),
		})
	}
}

func (m *InsecureDeserializationTesting) testPayload(ctx context.Context, p deserializationPayload) {
	atomic.AddInt64(&m.attemptedProbes, 1)

	// Baseline GET with a benign cookie value on the same cookie: framework
	// error markers can appear in ordinary pages (javadoc, dependency listings,
	// unrelated tracebacks), so a marker must be absent from the baseline
	// before it counts as deserialization proof.
	baseReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	baseReq.Header.Set("Cookie", fmt.Sprintf("%s=%s", p.cookie, "probe"))
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

	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}

	// Inject serialized object into a common session cookie. The payload is
	// URL-encoded so separators such as `;`, `=` and `+` inside the serialized
	// object survive server-side cookie parsing.
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", p.cookie, url.QueryEscape(p.payload)))

	resp, err := m.Client.Do(req)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	defer resp.Body.Close()

	// A 4xx/5xx response alone is not proof of processing, so it counts as an
	// unusable probe; judging still proceeds in case the error body leaks a
	// deserialization stack trace (results short-circuit the summary below).
	if resp.StatusCode >= http.StatusBadRequest {
		atomic.AddInt64(&m.failedProbes, 1)
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	bodyStr := string(bodyBytes)

	// Check for deserialization stack traces or errors; the marker must be
	// absent from the benign baseline response before it counts.
	if desBodyContainsMarker(bodyStr) && !desBodyContainsMarker(baseStr) {
		m.Mu.Lock()
		summary := "Insecure deserialization vulnerability detected using " + p.name
		detail := formatEvidenceDetail(EvidenceConfirmed, summary)
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, InsecureDeserializationTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("insecure_deserialization_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting InsecureDeserializationTesting on: %s", target))

		tester := NewInsecureDeserializationTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
