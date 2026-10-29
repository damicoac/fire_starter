// src/modules/component_version_analyzer.go
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ComponentVersionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ComponentVersionAnalyzer struct {
	BaseModule
	Target  string
	results []ComponentVersionResult
	seen    map[string]bool
}

func NewComponentVersionAnalyzer(target string) *ComponentVersionAnalyzer {
	return &ComponentVersionAnalyzer{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *ComponentVersionAnalyzer) Execute(ctx context.Context) ([]ComponentVersionResult, error) {
	m.results = make([]ComponentVersionResult, 0)
	m.seen = make(map[string]bool)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	m.passiveScan(ctx, m.Target)

	sensitiveFiles := []string{"/.env", "/package.json", "/composer.lock", "/wp-login.php", "/README.md"}

	var wg sync.WaitGroup
	for _, file := range sensitiveFiles {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				m.activeScan(ctx, parsedURL, path)
			}
		}(file)
	}
	wg.Wait()

	return m.results, nil
}

// passiveScan performs a non-intrusive scan of the target URL by making a GET request
// and analyzing the response headers and body for exposed component versions and technologies.
func (m *ComponentVersionAnalyzer) passiveScan(ctx context.Context, targetURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		m.addResult("Baseline request could not be built: "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.addResult("Baseline GET failed: "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}
	defer resp.Body.Close()

	// A non-2xx baseline means the target is not serving its normal surface;
	// attributing component versions to an error page would be noise, so gate
	// the scan like the other baseline-gated modules.
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		m.addResult(fmt.Sprintf("Baseline GET returned HTTP %d; component versions cannot be attributed to an error response", resp.StatusCode), statusFromEvidence(EvidenceWeak, false))
		return
	}

	if server := resp.Header.Get("Server"); server != "" {
		m.addResult("Found Server header: "+server+" (version comparison not performed)", statusFromEvidence(EvidenceWeak, false))
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		m.addResult("Found X-Powered-By header: "+poweredBy+" (version comparison not performed)", statusFromEvidence(EvidenceWeak, false))
	}
	if aspNet := resp.Header.Get("X-AspNet-Version"); aspNet != "" {
		m.addResult("Found X-AspNet-Version header: "+aspNet+" (version comparison not performed)", statusFromEvidence(EvidenceWeak, false))
	}

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.addResult("Baseline body read failed: "+err.Error(), statusFromEvidence(EvidenceWeak, false))
		return
	}
	bodyStr := string(bodyBytes)

	generatorRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := generatorRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		m.addResult("Found generator meta tag: "+matches[1]+" (version comparison not performed)", statusFromEvidence(EvidenceWeak, false))
	}

	scriptRegex := regexp.MustCompile(`(?i)<script\s+[^>]*src=["']([^"']+)["']`)
	for _, match := range scriptRegex.FindAllStringSubmatch(bodyStr, -1) {
		m.addResult("Found script source: "+match[1]+" (version comparison not performed)", statusFromEvidence(EvidenceWeak, false))
	}
}

// activeScan probes specific paths on the target to find exposed files or configurations
// (like .env or package.json) that might leak sensitive component version information.
func (m *ComponentVersionAnalyzer) activeScan(ctx context.Context, base *url.URL, path string) {
	testURL := *base
	testURL.Path = strings.TrimSuffix(base.Path, "/") + path

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
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

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return
	}
	bodyStr := string(bodyBytes)

	// Signatures were tightened so that soft-404/SPA pages no longer match:
	// README requires a markdown heading, package.json/composer.lock require
	// a JSON parse, .env requires an APP_* assignment and wp-login requires
	// the login form field.
	switch path {
	case "/.env":
		envLineRegex := regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]*=`)
		if envLineRegex.MatchString(bodyStr) {
			m.addResult("Found exposed configuration file: /.env (sensitive settings; no version information available)", statusFromEvidence(EvidenceWeak, false))
		}
	case "/package.json":
		var manifest struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal([]byte(bodyStr), &manifest); err == nil && manifest.Name != "" {
			if manifest.Version != "" {
				m.addResult(fmt.Sprintf("Found exposed configuration file: /package.json (name=%s, version=%s)", manifest.Name, manifest.Version), statusFromEvidence(EvidenceConfirmed, false))
			} else {
				m.addResult(fmt.Sprintf("Found exposed configuration file: /package.json (name=%s; version not declared)", manifest.Name), statusFromEvidence(EvidenceWeak, false))
			}
		}
	case "/composer.lock":
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal([]byte(bodyStr), &lock); err == nil && len(lock.Packages) > 0 {
			p := lock.Packages[0]
			if p.Version != "" {
				m.addResult(fmt.Sprintf("Found exposed configuration file: /composer.lock (%d packages; e.g. %s %s)", len(lock.Packages), p.Name, p.Version), statusFromEvidence(EvidenceConfirmed, false))
			} else {
				m.addResult(fmt.Sprintf("Found exposed configuration file: /composer.lock (%d packages; no versions declared)", len(lock.Packages)), statusFromEvidence(EvidenceWeak, false))
			}
		}
	case "/wp-login.php":
		if strings.Contains(bodyStr, "user_login") {
			m.addResult("Found exposed configuration file: /wp-login.php (WordPress login page)", statusFromEvidence(EvidenceWeak, false))
		}
	case "/README.md":
		readmeHeadingRegex := regexp.MustCompile(`(?m)^#{1,6} \S`)
		if readmeHeadingRegex.MatchString(bodyStr) {
			m.addResult("Found exposed configuration file: /README.md", statusFromEvidence(EvidenceWeak, false))
		}
	}
}

func (m *ComponentVersionAnalyzer) addResult(detail, status string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()

	parsed, _ := url.Parse(m.Target)
	host := ""
	if parsed != nil {
		host = parsed.Host
	}
	dedupKey := host + "|" + detail
	if m.seen[dedupKey] {
		return
	}
	m.seen[dedupKey] = true

	m.results = append(m.results, ComponentVersionResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
}

func init() {
	RegisterModule("component_version_analyzer", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting ComponentVersionAnalyzer on: %s", target))

		tester := NewComponentVersionAnalyzer(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
