package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// BrokenFunctionLevelAuthorizationBflaResult holds the result of the BrokenFunctionLevelAuthorizationBfla module execution.
type BrokenFunctionLevelAuthorizationBflaResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BrokenFunctionLevelAuthorizationBfla executes the broken_function_level_authorization_bfla security technique.
type BrokenFunctionLevelAuthorizationBfla struct {
	Target string
	BaseModule
	results []BrokenFunctionLevelAuthorizationBflaResult
}

// NewBrokenFunctionLevelAuthorizationBfla creates a new instance.
func NewBrokenFunctionLevelAuthorizationBfla(target string) *BrokenFunctionLevelAuthorizationBfla {
	return &BrokenFunctionLevelAuthorizationBfla{
		Target: EnsureHTTPPrefix(target),
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
	}
}

func (m *BrokenFunctionLevelAuthorizationBfla) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var adminPaths = []string{
	"/admin",
	"/api/admin",
	"/api/v1/admin",
	"/administrator",
	"/manage",
	"/config",
}

func (m *BrokenFunctionLevelAuthorizationBfla) getBaselineLength(ctx context.Context) int {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target+"/nonexistent_admin_path_12345", nil)
	if err != nil {
		return 0
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return len(body)
}

func (m *BrokenFunctionLevelAuthorizationBfla) Execute(ctx context.Context) ([]BrokenFunctionLevelAuthorizationBflaResult, error) {
	m.results = make([]BrokenFunctionLevelAuthorizationBflaResult, 0)
	baselineLen := m.getBaselineLength(ctx)

	jobs := make(chan string, len(adminPaths))
	for _, p := range adminPaths {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPath(ctx, path, baselineLen)
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

func (m *BrokenFunctionLevelAuthorizationBfla) testPath(ctx context.Context, path string, baselineLen int) {
	testURL := m.Target + path

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	respLen := len(bodyBytes)

	// If we get a 200 OK on an admin endpoint, ensure it's not a false positive
	if resp.StatusCode == http.StatusOK {
		diff := respLen - baselineLen
		if diff < 0 {
			diff = -diff
		}

		isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500

		if isSignificantlyDifferent {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Unauthenticated access to administrative endpoint: "+testURL)
			m.results = append(m.results, BrokenFunctionLevelAuthorizationBflaResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Unauthenticated access to administrative endpoint: " + testURL,
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("broken_function_level_authorization_bfla", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting BrokenFunctionLevelAuthorizationBfla on: %s", target))

		tester := NewBrokenFunctionLevelAuthorizationBfla(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
