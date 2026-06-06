package core

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
	BaseModule
	Target  string
	results []DOMBasedXSSAnalysisResult
}

// NewDOMBasedXSSAnalysis creates a new instance of DOMBasedXSSAnalysis.
func NewDOMBasedXSSAnalysis(target string) *DOMBasedXSSAnalysis {
	target = EnsureHTTPPrefix(target)
	return &DOMBasedXSSAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target, // Reasonable default concurrency
	}
}

// SetThreads sets the number of concurrent execution threads.
func (m *DOMBasedXSSAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	resp, err := m.Client.Do(req)
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

	for i := 0; i < m.MaxThreads; i++ {
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

	resp, err := m.Client.Do(req)
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

			// To avoid massive false positives (since innerHTML is everywhere),
			// only flag as vulnerable if BOTH a sink and a controllable source are found on the same line.
			if sourceMatch != "" {
				m.Mu.Lock()
				m.RecordPoC(nil, nil, "DOM XSS Sink ("+sinkMatch+") and Source ("+sourceMatch+") found on the same line.")
				m.results = append(m.results, DOMBasedXSSAnalysisResult{
					Target:    m.Target,
					ScriptURL: sourceURL,
					Line:      i + 1,
					Match:     strings.TrimSpace(line),
					Sink:      sinkMatch,
					Source:    sourceMatch,
				})
				m.Mu.Unlock()
			}
		}
	}
}

func init() {
	RegisterModule("dom_based_xss_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting DOMBasedXSSAnalysis on: %s", target))

		tester := NewDOMBasedXSSAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
