package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []BrokenObjectLevelAuthorizationBolaResult
	client     *http.Client
}

// NewBrokenObjectLevelAuthorizationBola creates a new instance.
func NewBrokenObjectLevelAuthorizationBola(target string) *BrokenObjectLevelAuthorizationBola {
	return &BrokenObjectLevelAuthorizationBola{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *BrokenObjectLevelAuthorizationBola) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *BrokenObjectLevelAuthorizationBola) Execute(ctx context.Context) ([]BrokenObjectLevelAuthorizationBolaResult, error) {
	m.results = make([]BrokenObjectLevelAuthorizationBolaResult, 0)

	// In a real attack, we'd take a known base ID and iterate up/down. Let's just fuzz IDs 1-10.
	jobs := make(chan string, 10)
	for i := 1; i <= 10; i++ {
		jobs <- strconv.Itoa(i)
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testID(ctx, id)
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

func (m *BrokenObjectLevelAuthorizationBola) testID(ctx context.Context, id string) {
	testURL := m.Target + "/api/users/" + id

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// If we can read arbitrary users without auth, that's BOLA
	if resp.StatusCode == http.StatusOK {
		m.mu.Lock()
		m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Unauthorized access to object at: " + testURL,
		})
		m.mu.Unlock()
	}
}
