package core

import (
	"context"
	"fmt"
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
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
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
	// Extract inline <script> blocks so prose outside script data is never
	// treated as JavaScript.
	scriptBlockRegex = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
)

// domXSSSinkSourceWindow is the maximum character distance between a sink and
// a source for them to be treated as the same data flow.
const domXSSSinkSourceWindow = 200

// Execute performs the module's core tasks concurrently.
func (m *DOMBasedXSSAnalysis) Execute(ctx context.Context) ([]DOMBasedXSSAnalysisResult, error) {
	m.Mu.Lock()
	m.results = make([]DOMBasedXSSAnalysisResult, 0)
	m.Mu.Unlock()

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

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read target body: %w", err)
	}

	htmlContent := string(body)

	// Analyze inline scripts (only inside real <script> blocks).
	m.analyzeHTML(m.Target, htmlContent, 0)

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

	for range m.MaxThreads {
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
		m.addInconclusive(scriptURL, fmt.Sprintf("Script request could not be built for %s: %v", scriptURL, err))
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.addInconclusive(scriptURL, fmt.Sprintf("Script fetch failed for %s: %v", scriptURL, err))
		return
	}
	defer resp.Body.Close()

	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.addInconclusive(scriptURL, fmt.Sprintf("Script body read failed for %s: %v", scriptURL, err))
		return
	}

	if resp.StatusCode != http.StatusOK {
		m.addInconclusive(scriptURL, fmt.Sprintf("Script fetch returned HTTP %d for %s; analysis skipped.", resp.StatusCode, scriptURL))
		return
	}

	m.analyzeJS(scriptURL, string(body), 0)
}

// analyzeHTML extracts inline <script> blocks from HTML content and analyzes
// each as JavaScript. Prose outside script blocks is never matched, which
// removes the false positives the earlier page-wide regex pass produced.
func (m *DOMBasedXSSAnalysis) analyzeHTML(sourceURL, content string, baseLine int) {
	for _, loc := range scriptBlockRegex.FindAllStringSubmatchIndex(content, -1) {
		lineOffset := baseLine + strings.Count(content[:loc[2]], "\n")
		m.analyzeJS(sourceURL, content[loc[2]:loc[3]], lineOffset)
	}
}

// analyzeJS scans JavaScript content for source/sink pairs on the same line
// within a bounded character window. Comments and string literals are stripped
// first (positions are preserved), and sinks must appear in call or
// assignment syntax.
func (m *DOMBasedXSSAnalysis) analyzeJS(sourceURL, content string, baseLine int) {
	stripped := stripJSCommentsAndStrings(content)
	lines := strings.Split(stripped, "\n")
	for i, line := range lines {
		sourceMatches := sourcesRegex.FindAllStringIndex(line, -1)
		if len(sourceMatches) == 0 {
			continue
		}
		seen := make(map[string]bool)
		for _, sinkLoc := range sinksRegex.FindAllStringIndex(line, -1) {
			if !domXSSSinkHasCallOrAssign(line, sinkLoc[1]) {
				continue
			}
			sink := line[sinkLoc[0]:sinkLoc[1]]
			for _, srcLoc := range sourceMatches {
				source := line[srcLoc[0]:srcLoc[1]]
				abs := sinkLoc[0] - srcLoc[0]
				if abs < 0 {
					abs = -abs
				}
				if abs > domXSSSinkSourceWindow {
					continue
				}
				key := sink + "|" + source
				if seen[key] {
					continue
				}
				seen[key] = true
				m.addFinding(sourceURL, baseLine+i+1, boundedSnippet(line, sinkLoc[0], srcLoc[0]), sink, source)
			}
		}
	}
}

// domXSSSinkHasCallOrAssign requires call syntax (`eval(`) or an assignment
// (`x.innerHTML = ...`) directly after the sink name, so mentions inside
// identifiers, comments, or prose do not count.
func domXSSSinkHasCallOrAssign(line string, matchEnd int) bool {
	rest := strings.TrimLeft(line[matchEnd:], " \t")
	return len(rest) > 0 && (rest[0] == '(' || rest[0] == '=' || rest[0] == '+')
}

func boundedSnippet(line string, positions ...int) string {
	lo, hi := len(line), 0
	for _, p := range positions {
		if p < lo {
			lo = p
		}
		if p > hi {
			hi = p
		}
	}
	start := lo - 80
	if start < 0 {
		start = 0
	}
	end := hi + 80
	if end > len(line) {
		end = len(line)
	}
	return strings.TrimSpace(line[start:end])
}

// stripJSCommentsAndStrings replaces comment and string-literal content with
// spaces (preserving byte offsets and newlines) so identifiers mentioned
// inside strings or comments are no longer treated as code.
func stripJSCommentsAndStrings(content string) string {
	var b strings.Builder
	b.Grow(len(content))
	inLine, inBlock := false, false
	var inStr byte
	escaped := false

	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
		case inBlock:
			if c == '*' && i+1 < len(content) && content[i+1] == '/' {
				inBlock = false
				b.WriteString("  ")
				i++
			} else {
				b.WriteByte(' ')
			}
		case inStr != 0:
			switch {
			case escaped:
				escaped = false
				b.WriteByte(' ')
			case c == '\\':
				escaped = true
				b.WriteByte(' ')
			case c == inStr:
				inStr = 0
				b.WriteByte(c)
			default:
				b.WriteByte(' ')
			}
		case c == '/' && i+1 < len(content) && content[i+1] == '/':
			inLine = true
			b.WriteString("  ")
			i++
		case c == '/' && i+1 < len(content) && content[i+1] == '*':
			inBlock = true
			b.WriteString("  ")
			i++
		case c == '\'' || c == '"' || c == '`':
			inStr = c
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// addFinding records a confirmed DOM source/sink pair.
func (m *DOMBasedXSSAnalysis) addFinding(sourceURL string, line int, match, sink, source string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	detail := fmt.Sprintf("DOM sink %s consumes controllable source %s at %s line %d", sink, source, sourceURL, line)
	m.results = append(m.results, DOMBasedXSSAnalysisResult{
		Target:    m.Target,
		ScriptURL: sourceURL,
		Line:      line,
		Match:     match,
		Sink:      sink,
		Source:    source,
		Status:    statusFromEvidence(EvidenceConfirmed, false),
		Detail:    formatEvidenceDetail(EvidenceConfirmed, detail),
	})
}

// addInconclusive records an inconclusive row for a fetch failure
// (deduplicated by detail so repeated failures do not flood the report).
func (m *DOMBasedXSSAnalysis) addInconclusive(scriptURL, detail string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	for _, r := range m.results {
		if r.Status == "inconclusive" && r.Detail == formatEvidenceDetail(EvidenceWeak, detail) {
			return
		}
	}
	m.results = append(m.results, DOMBasedXSSAnalysisResult{
		Target:    m.Target,
		ScriptURL: scriptURL,
		Status:    statusFromEvidence(EvidenceWeak, false),
		Detail:    formatEvidenceDetail(EvidenceWeak, detail),
	})
}

func init() {
	RegisterModule("dom_based_xss_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
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
