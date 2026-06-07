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
	Target        string
	results       []HttpVerbTamperingResult
	baselineGet   ResponseBaseline
	baselineBogus ResponseBaseline
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

var verbsToTest = []string{
	"OPTIONS", "HEAD", "CONNECT", "PUT", "DELETE", "TRACE", "TRACK", "PATCH",
	"GeT", "POst", "pUT", // case variations
	"BOGUSVERB",          // arbitrary verb
}

func (m *HttpVerbTampering) runBaseline(ctx context.Context) {
	m.baselineGet = m.fetchBaseline(ctx, "GET")
	m.baselineBogus = m.fetchBaseline(ctx, "JEAN_BOGUS_VERB")
}

func (m *HttpVerbTampering) fetchBaseline(ctx context.Context, verb string) ResponseBaseline {
	req, err := http.NewRequestWithContext(ctx, verb, m.Target, nil)
	if err != nil {
		return ResponseBaseline{}
	}

	if m.Cookies != "" {
		req.Header.Set("Cookie", m.Cookies)
	}
	for k, v := range m.OriginalHeaders {
		req.Header[k] = v
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return ResponseBaseline{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ResponseBaseline{
		StatusCode: resp.StatusCode,
		Length:     int64(len(body)),
	}
}

func (m *HttpVerbTampering) Execute(ctx context.Context) ([]HttpVerbTamperingResult, error) {
	m.results = make([]HttpVerbTamperingResult, 0)

	m.runBaseline(ctx)

	jobs := make(chan string, len(verbsToTest))
	for _, v := range verbsToTest {
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *HttpVerbTampering) testVerb(ctx context.Context, verb string) {
	var bodyReader io.Reader
	var bodyBytes []byte

	// For state-changing verbs, add a generic JSON payload
	isStateChanging := false
	switch strings.ToUpper(verb) {
	case "PUT", "POST", "PATCH", "DELETE":
		isStateChanging = true
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

	if m.Cookies != "" {
		req.Header.Set("Cookie", m.Cookies)
	}
	for k, v := range m.OriginalHeaders {
		req.Header[k] = v
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respLength := int64(len(respBody))

	// Analysis
	isVulnerable := false
	detail := ""

	// 1. Authentication/Authorization Bypass
	// If GET requires auth (401/403) but this verb returns 2xx OK
	if (m.baselineGet.StatusCode == http.StatusUnauthorized || m.baselineGet.StatusCode == http.StatusForbidden) &&
		(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		// Ensure it's not just returning 200 OK for everything indiscriminately
		if resp.StatusCode != m.baselineBogus.StatusCode || respLength != m.baselineBogus.Length {
			isVulnerable = true
			detail = fmt.Sprintf("Authentication bypass detected. GET returned %d, but %s returned %d.", m.baselineGet.StatusCode, verb, resp.StatusCode)
		}
	}

	// 2. Successful Execution of State-Changing Verbs
	if !isVulnerable && isStateChanging && (resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK) {
		// It might be vulnerable if it accepted a PUT/DELETE, especially if it differs from BOGUS
		if resp.StatusCode != m.baselineBogus.StatusCode || respLength != m.baselineBogus.Length {
			// Might be a false positive if it's identical to GET, so check that too
			if resp.StatusCode != m.baselineGet.StatusCode || respLength != m.baselineGet.Length {
				isVulnerable = true
				detail = fmt.Sprintf("State-changing verb %s accepted. Returned %d (differing from baselines).", verb, resp.StatusCode)
			}
		}
	}

	// 3. WAF / Filter Bypass (Case Sensitivity)
	if !isVulnerable && strings.ToUpper(verb) != verb && (resp.StatusCode >= 200 && resp.StatusCode < 300) {
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

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
