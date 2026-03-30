package modules

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionFixationTestingResult holds the result of the SessionFixationTesting module execution.
type SessionFixationTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SessionFixationTesting executes the session_fixation_testing security technique.
type SessionFixationTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []SessionFixationTestingResult
	client     *http.Client
}

// NewSessionFixationTesting creates a new instance.
func NewSessionFixationTesting(target string) *SessionFixationTesting {
	return &SessionFixationTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 2,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *SessionFixationTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *SessionFixationTesting) Execute(ctx context.Context) ([]SessionFixationTestingResult, error) {
	m.results = make([]SessionFixationTestingResult, 0)

	// Since we don't have real credentials, we just simulate the flow:
	// 1. Send a request with a fake predetermined session ID
	// 2. See if the server accepts it or forces a new one
	
	sessionNames := []string{"PHPSESSID", "JSESSIONID", "session_id", "ASP.NET_SessionId"}
	
	jobs := make(chan string, len(sessionNames))
	for _, s := range sessionNames {
		jobs <- s
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cookieName := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testCookie(ctx, cookieName)
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

func (m *SessionFixationTesting) testCookie(ctx context.Context, cookieName string) {
	fakeSessionID := "1234567890abcdef1234567890abcdef"
	
	// Simulate login request (or any request)
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("username=test&password=test"))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: fakeSessionID})

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if the server issued a new session ID to replace ours
	replaced := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName {
			replaced = true
			if cookie.Value == fakeSessionID {
				// Server echoed our fake session ID back without changing it
				m.mu.Lock()
				m.results = append(m.results, SessionFixationTestingResult{
					Target: m.Target,
					Status: "vulnerable",
					Detail: "Potential Session Fixation: Server accepted and retained fake session ID for " + cookieName,
				})
				m.mu.Unlock()
			}
		}
	}
	
	if !replaced && resp.StatusCode == 200 {
		// Server didn't issue any cookies, might just be accepting ours silently
		m.mu.Lock()
		m.results = append(m.results, SessionFixationTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential Session Fixation: Server did not rotate the pre-authenticated session cookie " + cookieName,
		})
		m.mu.Unlock()
	}
}
