package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GoogleDorkingResult holds the result of the GoogleDorking module execution.
type GoogleDorkingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// GoogleDorking executes the google_dorking security technique.
type GoogleDorking struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []GoogleDorkingResult
	client     *http.Client
}

// NewGoogleDorking creates a new instance.
func NewGoogleDorking(target string) *GoogleDorking {
	return &GoogleDorking{
		Target:     target, // The target should be a domain
		maxThreads: 2,      // Low concurrency so Google doesn't block us immediately
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *GoogleDorking) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var dorks = []string{
	"ext:sql OR ext:db OR ext:sqlite OR ext:dump",
	"ext:env OR ext:log OR ext:yml OR ext:json",
	"intitle:\"index of\"",
	"inurl:admin OR inurl:login",
}

func (m *GoogleDorking) Execute(ctx context.Context) ([]GoogleDorkingResult, error) {
	m.results = make([]GoogleDorkingResult, 0)

	targetDomain := strings.TrimPrefix(m.Target, "http://")
	targetDomain = strings.TrimPrefix(targetDomain, "https://")
	targetDomain = strings.Split(targetDomain, "/")[0]
	targetDomain = strings.Split(targetDomain, ":")[0]

	jobs := make(chan string, len(dorks))
	for _, d := range dorks {
		jobs <- fmt.Sprintf("site:%s %s", targetDomain, d)
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for query := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testDork(ctx, query)
					// Small delay to prevent instant ban
					time.Sleep(2 * time.Second)
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

func (m *GoogleDorking) testDork(ctx context.Context, query string) {
	// Send to DuckDuckGo HTML version to avoid Google's strict Captcha, as it's easier to parse for a simple module
	searchURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

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

	// If DuckDuckGo returns results (look for class result__url or similar)
	if strings.Contains(bodyStr, "result__url") && !strings.Contains(bodyStr, "No results.") {
		m.mu.Lock()
		m.results = append(m.results, GoogleDorkingResult{
			Target: m.Target,
			Status: "found",
			Detail: "Search engine found results for dork: " + query,
		})
		m.mu.Unlock()
	}
}
