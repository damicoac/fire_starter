// src/modules/component_version_analyzer.go
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

type ComponentVersionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ComponentVersionAnalyzer struct {
	BaseModule
	Target  string
	results []ComponentVersionResult
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
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if server := resp.Header.Get("Server"); server != "" {
		m.addResult("Found Server header: " + server)
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		m.addResult("Found X-Powered-By header: " + poweredBy)
	}
	if aspNet := resp.Header.Get("X-AspNet-Version"); aspNet != "" {
		m.addResult("Found X-AspNet-Version header: " + aspNet)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err == nil {
		bodyStr := string(bodyBytes)

		generatorRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
		if matches := generatorRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
			m.addResult("Found generator meta tag: " + matches[1])
		}

		scriptRegex := regexp.MustCompile(`(?i)<script\s+[^>]*src=["']([^"']+)["']`)
		for _, match := range scriptRegex.FindAllStringSubmatch(bodyStr, -1) {
			m.addResult("Found script source: " + match[1])
		}
	}
}

// activeScan probes specific paths on the target to find exposed files or configurations
// (like .env or package.json) that might leak sensitive component version information.
func (m *ComponentVersionAnalyzer) activeScan(ctx context.Context, base *url.URL, path string) {
	testURL := *base
	testURL.Path = path

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err == nil {
			bodyStr := string(bodyBytes)
			matched := false

			switch path {
			case "/.env":
				if strings.Contains(bodyStr, "APP_ENV") {
					matched = true
				}
			case "/package.json":
				if strings.Contains(bodyStr, "\"name\"") {
					matched = true
				}
			case "/composer.lock":
				if strings.Contains(bodyStr, "\"packages\"") {
					matched = true
				}
			case "/wp-login.php":
				if strings.Contains(bodyStr, "user_login") {
					matched = true
				}
			case "/README.md":
				if strings.Contains(bodyStr, "#") {
					matched = true
				}
			}

			if matched {
				m.addResult("Found exposed configuration file: " + path)
			}
		}
	}
}

func (m *ComponentVersionAnalyzer) addResult(detail string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.RecordPoC(nil, nil, detail)
	m.results = append(m.results, ComponentVersionResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: detail,
	})
}

func init() {
	RegisterModule("component_version_analyzer", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
