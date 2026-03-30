package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BufferOverflowProbingResult holds the result of the BufferOverflowProbing module execution.
type BufferOverflowProbingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BufferOverflowProbing executes the buffer_overflow_probing security technique.
type BufferOverflowProbing struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []BufferOverflowProbingResult
	client     *http.Client
}

// NewBufferOverflowProbing creates a new instance.
func NewBufferOverflowProbing(target string) *BufferOverflowProbing {
	return &BufferOverflowProbing{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 2,
		client:     NewHTTPClient(15 * time.Second),
	}
}

func (m *BufferOverflowProbing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *BufferOverflowProbing) Execute(ctx context.Context) ([]BufferOverflowProbingResult, error) {
	m.results = make([]BufferOverflowProbingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	lengths := []int{1000, 10000, 50000}
	jobs := make(chan string, len(lengths))
	for _, l := range lengths {
		jobs <- strings.Repeat("A", l)
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

func (m *BufferOverflowProbing) testPayload(ctx context.Context, u *url.URL, payload string) {
	query := u.Query()
	testURL := *u

	if len(query) > 0 {
		for key := range query {
			query.Set(key, payload)
		}
		testURL.RawQuery = query.Encode()
	} else {
		query.Add("input", payload)
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

	if resp.StatusCode == http.StatusInternalServerError {
		m.mu.Lock()
		m.results = append(m.results, BufferOverflowProbingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Large input buffer caused HTTP 500 Internal Server Error (Length: " + string(rune(len(payload))) + ")",
		})
		m.mu.Unlock()
	}
}
