package core

import (
	"context"
	"fmt"
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
	BaseModule
	Target  string
	results []GoogleDorkingResult
}

// NewGoogleDorking creates a new instance.
func NewGoogleDorking(target string) *GoogleDorking {
	return &GoogleDorking{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target, // The target should be a domain      // Low concurrency so Google doesn't block us immediately
	}
}

func (m *GoogleDorking) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var dorks = []string{
	"filetype:sql OR filetype:db OR filetype:sqlite OR filetype:dump",
	"filetype:env OR filetype:log OR filetype:yml OR filetype:json",
	"intitle:\"index of\"",
	"intitle:\"index of\" (\".env\" OR \".sql\" OR \".bak\")",
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

	for i := 0; i < m.MaxThreads; i++ {
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
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
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
		m.addResult("Dork request could not be built: "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.Client.Do(req)
	if err != nil {
		m.addResult("Search engine request failed for dork "+query+": "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.addResult(fmt.Sprintf("Search engine returned status %d for dork: %s", resp.StatusCode, query), statusFromEvidence(EvidenceWeak, false))
		return
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.addResult("Search engine response read failed for dork "+query+": "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}

	bodyStr := string(bodyBytes)

	// Bot-challenge pages look like clean "no results" runs if not detected:
	// report them as inconclusive instead of silently empty.
	challengeMarkers := []string{"anomaly-modal", "challenge-form", "Unfortunately, bots use DuckDuckGo too"}
	for _, marker := range challengeMarkers {
		if strings.Contains(bodyStr, marker) {
			m.addResult("Search engine bot challenge detected for dork: "+query, statusFromEvidence(EvidenceWeak, false))
			return
		}
	}

	// Result links present means exposures were found; a snippet that merely
	// contains the text "No results." must not downgrade a real result page.
	if strings.Contains(bodyStr, "result__url") {
		m.addResult("Search engine found results for dork: "+query, statusFromEvidence(EvidenceConfirmed, false))
		return
	}

	// "secure" is only reportable when the engine explicitly said there were no
	// results; anything else is an unrecognised page layout.
	if strings.Contains(bodyStr, "No results.") {
		m.addResult("No results found for dork: "+query, statusFromEvidence(EvidenceConfirmed, true))
		return
	}

	m.addResult("Unrecognised search engine response layout for dork "+query+"; results could not be classified.", statusFromEvidence(EvidenceWeak, false))
}

func (m *GoogleDorking) addResult(detail, status string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.results = append(m.results, GoogleDorkingResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
}

func init() {
	RegisterModule("google_dorking", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting GoogleDorking on: %s", target))

		tester := NewGoogleDorking(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
