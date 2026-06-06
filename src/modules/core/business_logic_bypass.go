package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type BusinessLogicBypassResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type BusinessLogicBypass struct {
	BaseModule
	Target  string
	results []BusinessLogicBypassResult
}

func NewBusinessLogicBypass(target string) *BusinessLogicBypass {
	return &BusinessLogicBypass{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *BusinessLogicBypass) Execute(ctx context.Context) ([]BusinessLogicBypassResult, error) {
	m.results = make([]BusinessLogicBypassResult, 0)

	endpoints := []string{
		"/api/checkout/complete",
		"/checkout/complete",
		"/order/confirm",
		"/payment/process",
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testLogicBypass(ctx, ep)
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *BusinessLogicBypass) testLogicBypass(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint

	// Try to hit a completion endpoint without session or prior steps
	req, err := http.NewRequestWithContext(ctx, "POST", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(bodyBytes))

	// If the server doesn't reject us immediately with a 401/403 or logic error
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		if strings.Contains(bodyStr, "success") || strings.Contains(bodyStr, "confirmed") {
			m.Mu.Lock()
			m.RecordPoC(req, nil, fmt.Sprintf("Potential Business Logic Bypass at: %s", testURL))
			m.results = append(m.results, BusinessLogicBypassResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Accessed final step endpoint %s successfully without context", testURL),
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("business_logic_bypass", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting BusinessLogicBypass on: %s", target))
		tester := NewBusinessLogicBypass(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
