package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// BrokenObjectLevelAuthorizationBolaResult holds the result of the BrokenObjectLevelAuthorizationBola module execution.
type BrokenObjectLevelAuthorizationBolaResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BrokenObjectLevelAuthorizationBola executes the broken_object_level_authorization_bola security technique.
type BrokenObjectLevelAuthorizationBola struct {
	BaseModule
	Target  string
	results []BrokenObjectLevelAuthorizationBolaResult
}

// NewBrokenObjectLevelAuthorizationBola creates a new instance.
func NewBrokenObjectLevelAuthorizationBola(target string) *BrokenObjectLevelAuthorizationBola {
	return &BrokenObjectLevelAuthorizationBola{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *BrokenObjectLevelAuthorizationBola) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *BrokenObjectLevelAuthorizationBola) getBaselineLength(ctx context.Context) int {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target+"/api/users/999999999", nil)
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

func (m *BrokenObjectLevelAuthorizationBola) Execute(ctx context.Context) ([]BrokenObjectLevelAuthorizationBolaResult, error) {
	m.results = make([]BrokenObjectLevelAuthorizationBolaResult, 0)
	baselineLen := m.getBaselineLength(ctx)

	// In a real attack, we'd take a known base ID and iterate up/down. Let's just fuzz IDs 1-10.
	jobs := make(chan string, 10)
	for i := 1; i <= 10; i++ {
		jobs <- strconv.Itoa(i)
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testID(ctx, id, baselineLen)
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

func (m *BrokenObjectLevelAuthorizationBola) testID(ctx context.Context, id string, baselineLen int) {
	testURL := m.Target + "/api/users/" + id

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

	// If we can read arbitrary users without auth, ensure it differs from baseline
	if resp.StatusCode == http.StatusOK {
		diff := respLen - baselineLen
		if diff < 0 {
			diff = -diff
		}
		
		isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500
		
		if isSignificantlyDifferent {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Unauthorized access to object at: "+testURL)
			m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Unauthorized access to object at: " + testURL,
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("broken_object_level_authorization_bola", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting BrokenObjectLevelAuthorizationBola on: %s", target))

		tester := NewBrokenObjectLevelAuthorizationBola(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
