package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DOMBasedXSSAnalysisResult holds the result of the DOMBasedXSSAnalysis module execution.
type DOMBasedXSSAnalysisResult struct {
	Target    string `json:"target"`
	ScriptURL string `json:"script_url"`
	Line      int    `json:"line"`
	Match     string `json:"match"`
	Sink      string `json:"sink"`
	Source    string `json:"source,omitempty"`
}

// DOMBasedXSSAnalysis executes the dom_based_xss_analysis security technique.
// Description: fuzz client-side JavaScript for 'sinks' that process data from controllable 'sources' like the URL fragment
type DOMBasedXSSAnalysis struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []DOMBasedXSSAnalysisResult
	client     *http.Client
}

// NewDOMBasedXSSAnalysis creates a new instance of DOMBasedXSSAnalysis.
func NewDOMBasedXSSAnalysis(target string) *DOMBasedXSSAnalysis {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	return &DOMBasedXSSAnalysis{
		Target:     target,
		maxThreads: 10, // Reasonable default concurrency
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetThreads sets the number of concurrent execution threads.
func (m *DOMBasedXSSAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var (
	// Common DOM XSS sinks
	sinksRegex = regexp.MustCompile(`(?i)\b(innerHTML|outerHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|location\.replace|location\.assign)\b`)
	// Common DOM XSS sources
	sourcesRegex = regexp.MustCompile(`(?i)\b(location\.hash|location\.search|location\.pathname|document\.referrer|window\.name|document\.cookie|postMessage)\b`)
	// Extract script src
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
)

// Execute performs the module's core tasks concurrently.
func (m *DOMBasedXSSAnalysis) Execute(ctx context.Context) ([]DOMBasedXSSAnalysisResult, error) {
	m.results = make([]DOMBasedXSSAnalysisResult, 0)

	// Step 1: Fetch the target page to find scripts
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch target: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read target body: %w", err)
	}

	htmlContent := string(body)

	// Analyze inline scripts (rough approximation by analyzing the whole HTML)
	m.analyzeContent(m.Target, htmlContent)

	// Step 2: Extract external script URLs
	matches := scriptSrcRegex.FindAllStringSubmatch(htmlContent, -1)
	var scriptURLs []string
	seenURLs := make(map[string]bool)

	parsedTarget, err := url.Parse(m.Target)
	if err != nil {
		return m.results, nil // return what we have
	}

	for _, match := range matches {
		if len(match) > 1 {
			src := match[1]
			
			// Resolve relative URLs
			scriptURL, err := parsedTarget.Parse(src)
			if err != nil {
				continue
			}

			// Only analyze scripts from the same domain to avoid noise/scope issues
			if scriptURL.Host != parsedTarget.Host {
				continue
			}

			s := scriptURL.String()
			if !seenURLs[s] {
				seenURLs[s] = true
				scriptURLs = append(scriptURLs, s)
			}
		}
	}

	// Step 3: Fetch and analyze external scripts concurrently
	jobs := make(chan string, len(scriptURLs))
	for _, s := range scriptURLs {
		jobs <- s
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.fetchAndAnalyzeScript(ctx, job)
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

func (m *DOMBasedXSSAnalysis) fetchAndAnalyzeScript(ctx context.Context, scriptURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	m.analyzeContent(scriptURL, string(body))
}

func (m *DOMBasedXSSAnalysis) analyzeContent(sourceURL, content string) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		// Optimization: only check if line length is reasonable
		if len(line) > 1000 {
			line = line[:1000] // truncate very long lines
		}

		sinkMatch := sinksRegex.FindString(line)
		if sinkMatch != "" {
			sourceMatch := sourcesRegex.FindString(line)
			
			// To reduce false positives, we mainly care if both a source and sink are near each other,
			// or if a major sink is present. Let's report any sink found, but note the source if present.
			
			m.mu.Lock()
			m.results = append(m.results, DOMBasedXSSAnalysisResult{
				Target:    m.Target,
				ScriptURL: sourceURL,
				Line:      i + 1,
				Match:     strings.TrimSpace(line),
				Sink:      sinkMatch,
				Source:    sourceMatch,
			})
			m.mu.Unlock()
		}
	}
}
