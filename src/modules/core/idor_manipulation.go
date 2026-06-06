package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// IDORManipulationResult holds the result of the IDORManipulation module execution.
type IDORManipulationResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// IDORManipulation executes the idor_manipulation security technique.
type IDORManipulation struct {
	BaseModule
	Target  string
	results []IDORManipulationResult
}

// NewIDORManipulation creates a new instance.
func NewIDORManipulation(target string) *IDORManipulation {
	return &IDORManipulation{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *IDORManipulation) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *IDORManipulation) getBaselineLength(ctx context.Context, u *url.URL) int {
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
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

var idorIds = []string{"1", "001", "admin", "1000"}

func (m *IDORManipulation) Execute(ctx context.Context) ([]IDORManipulationResult, error) {
	m.results = make([]IDORManipulationResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	baselineLen := m.getBaselineLength(ctx, parsedURL)

	jobs := make(chan string, len(idorIds))
	for _, p := range idorIds {
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
					m.testPayload(ctx, parsedURL, payload, baselineLen)
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

func (m *IDORManipulation) testPayload(ctx context.Context, u *url.URL, payload string, baselineLen int) {
	query := u.Query()
	hasParams := len(query) > 0

	testURL := *u
	if hasParams {
		for key := range query {
			query.Set(key, payload)
		}
		testURL.RawQuery = query.Encode()
	} else {
		query.Add("user_id", payload)
		query.Add("account_id", payload)
		testURL.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
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

	if resp.StatusCode == http.StatusOK {
		// Differential analysis: does it differ significantly from the baseline?
		diff := respLen - baselineLen
		if diff < 0 {
			diff = -diff
		}
		
		// If difference is > 10% or > 500 bytes, consider it an IDOR
		isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500

		if isSignificantlyDifferent {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Potential IDOR found. Reached object with ID "+payload+" at "+testURL.String())
			m.results = append(m.results, IDORManipulationResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Potential IDOR found. Reached object with ID " + payload + " at " + testURL.String(),
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("idor_manipulation", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting IDORManipulation on: %s", target))

		tester := NewIDORManipulation(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
