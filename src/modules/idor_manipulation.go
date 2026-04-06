package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []IDORManipulationResult
	client     *http.Client
}

// NewIDORManipulation creates a new instance.
func NewIDORManipulation(target string) *IDORManipulation {
	return &IDORManipulation{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *IDORManipulation) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var idorIds = []string{"1", "001", "admin", "1000"}

func (m *IDORManipulation) Execute(ctx context.Context) ([]IDORManipulationResult, error) {
	m.results = make([]IDORManipulationResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(idorIds))
	for _, p := range idorIds {
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
					m.testPayload(ctx, parsedURL, payload)
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

func (m *IDORManipulation) testPayload(ctx context.Context, u *url.URL, payload string) {
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

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		m.mu.Lock()
		m.results = append(m.results, IDORManipulationResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential IDOR found. Reached object with ID " + payload + " at " + testURL.String(),
		})
		m.mu.Unlock()
	}
}
