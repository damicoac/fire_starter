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
					m.testDork(ctx, query, targetDomain)
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

func (m *GoogleDorking) testDork(ctx context.Context, query, targetDomain string) {
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

	// A dork "hit" requires at least one extracted result-link host that
	// suffix-matches the target domain; indexed existence is an inventory
	// note, not a confirmed vulnerability.
	if strings.Contains(bodyStr, "result__url") {
		matchedHost := ""
		for _, host := range extractResultLinkHosts(bodyStr) {
			if hostSuffixMatches(host, targetDomain) {
				matchedHost = host
				break
			}
		}
		if matchedHost != "" {
			m.addResult(fmt.Sprintf("Search engine found results for dork %s (result link host %s matches the target domain); review the indexed paths manually", query, matchedHost), "informational")
		} else {
			m.addResult("Search engine returned result links but none matched the target domain for dork "+query, statusFromEvidence(EvidenceWeak, false))
		}
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

// extractResultLinkHosts pulls href targets out of result__url blocks and
// returns their lowercased hostnames. The href attribute may precede or
// follow the result__url class marker inside the same anchor tag; the
// closest href on either side wins so a neighbouring anchor's link is never
// attributed to this result block.
func extractResultLinkHosts(body string) []string {
	parseHost := func(s string) (string, bool) {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname()), true
		}
		return "", false
	}
	firstHostAfter := func(s string) (string, bool) {
		hIdx := strings.Index(s, `href="`)
		if hIdx < 0 {
			return "", false
		}
		rest := s[hIdx+len(`href="`):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			return "", false
		}
		return parseHost(rest[:end])
	}

	var hosts []string
	for i := 0; i < len(body); {
		idx := strings.Index(body[i:], "result__url")
		if idx < 0 {
			break
		}
		start := i + idx

		after := body[start:]
		if len(after) > 512 {
			after = after[:512]
		}
		if host, ok := firstHostAfter(after); ok {
			hosts = append(hosts, host)
			i = start + len("result__url")
			continue
		}

		beforeStart := start - 256
		if beforeStart < 0 {
			beforeStart = 0
		}
		if last := strings.LastIndex(body[beforeStart:start], `href="`); last >= 0 {
			if host, ok := firstHostAfter(body[beforeStart+last:]); ok {
				hosts = append(hosts, host)
			}
		}
		i = start + len("result__url")
	}
	return hosts
}

// hostSuffixMatches reports whether a result-link host is the target domain
// itself or lives under it.
func hostSuffixMatches(host, domain string) bool {
	host = strings.TrimSuffix(host, ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
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
