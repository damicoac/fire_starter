package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type WebCrawler struct {
	BaseModule
	TargetURLs []string
	MaxDepth   int
}

func NewWebCrawler(target string, customURLs []string, maxDepth int) *WebCrawler {
	urls := customURLs
	if len(urls) == 0 {
		urls = []string{target}
	}
	return &WebCrawler{
		TargetURLs: urls,
		MaxDepth:   maxDepth,
		BaseModule: BaseModule{
			Client: NewHTTPClient(10 * time.Second),
		},
	}
}

func (c *WebCrawler) Crawl(ctx context.Context) ([]string, error) {
	if len(c.TargetURLs) == 0 {
		return nil, nil
	}

	// Use the first URL to establish the base domain scope
	baseURL, err := url.Parse(c.TargetURLs[0])
	if err != nil {
		return nil, err
	}

	visited := make(map[string]bool)
	resultSet := make(map[string]bool)
	var mu sync.Mutex
	var results []string

	const maxCrawledPages = 150
	maxConcurrency := c.MaxThreads
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}

	cookies := c.BaseModule.GetCookies()

	currentLevel := make([]string, 0, len(c.TargetURLs))
	for _, u := range c.TargetURLs {
		if !visited[u] {
			visited[u] = true
			currentLevel = append(currentLevel, u)
		}
	}

	for depth := 1; depth <= c.MaxDepth && len(currentLevel) > 0; depth++ {
		if ctx.Err() != nil {
			break
		}

		var nextLevel []string
		var nextLevelMu sync.Mutex

		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup

	LevelLoop:
		for _, currentURL := range currentLevel {
			if ctx.Err() != nil {
				break
			}
			mu.Lock()
			if len(results) >= maxCrawledPages {
				mu.Unlock()
				break
			}
			mu.Unlock()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break LevelLoop
			}

			wg.Add(1)
			go func(targetURL string) {
				defer wg.Done()
				defer func() { <-sem }()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
				if err != nil {
					return
				}

				if cookies != "" {
					req.Header.Set("Cookie", cookies)
				}

				client := c.Client
				if client == nil {
					client = http.DefaultClient
				}

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return
				}

				mu.Lock()
				if !resultSet[targetURL] {
					resultSet[targetURL] = true
					results = append(results, targetURL)
				}
				mu.Unlock()

				if depth >= c.MaxDepth {
					return
				}

				limitReader := io.LimitReader(resp.Body, 5*1024*1024)
				tokenizer := html.NewTokenizer(limitReader)
				for {
					tt := tokenizer.Next()
					if tt == html.ErrorToken {
						break
					}

					if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
						t := tokenizer.Token()
						var link string

						switch t.Data {
						case "a", "link":
							link = extractAttr(t.Attr, "href")
						case "script", "img", "iframe":
							link = extractAttr(t.Attr, "src")
						case "form":
							link = extractAttr(t.Attr, "action")
						}

						if link != "" {
							parsedLink, err := baseURL.Parse(link)
							if err == nil {
								parsedLink.Fragment = ""
								resolved := parsedLink.String()

								if parsedLink.Host == baseURL.Host {
									if isStaticAsset(resolved) {
										mu.Lock()
										if !resultSet[resolved] {
											resultSet[resolved] = true
											results = append(results, resolved)
										}
										mu.Unlock()
									} else {
										mu.Lock()
										if !visited[resolved] && len(results) < maxCrawledPages {
											visited[resolved] = true
											nextLevelMu.Lock()
											nextLevel = append(nextLevel, resolved)
											nextLevelMu.Unlock()
										}
										mu.Unlock()
									}
								}
							}
						}
					}
				}
			}(currentURL)
		}

		wg.Wait()
		currentLevel = nextLevel
	}

	return results, nil
}

func isStaticAsset(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	staticExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".mp4", ".mp3", ".avi", ".mov", ".webm",
		".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// ScanCommonPages scans a minimal set of highly common web endpoints
func (c *WebCrawler) ScanCommonPages(ctx context.Context) ([]string, error) {
	if len(c.TargetURLs) == 0 {
		return nil, nil
	}

	baseURL, err := url.Parse(c.TargetURLs[0])
	if err != nil {
		return nil, err
	}

	commonPaths := []string{
		"/",
		"/robots.txt",
		"/sitemap.xml",
		"/.env",
		"/.git/config",
		"/admin/",
		"/login.php",
		"/wp-admin/",
		"/api/",
	}

	var commonURLs []string
	for _, p := range commonPaths {
		u, _ := baseURL.Parse(p)
		commonURLs = append(commonURLs, u.String())
	}

	c.TargetURLs = commonURLs
	return c.Crawl(ctx)
}

func extractAttr(attrs []html.Attribute, key string) string {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func init() {
	RegisterModule("web_crawler", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		maxDepth := PayloadInt(payload, "max_depth", 2)
		onLog(fmt.Sprintf("Starting WebCrawler on: %s with depth %d", target, maxDepth))

		var customURLs []string
		if urlsAny, ok := payload["urls"].([]any); ok {
			for _, u := range urlsAny {
				if s, ok := u.(string); ok && s != "" {
					customURLs = append(customURLs, s)
				}
			}
		}

		crawler := NewWebCrawler(target, customURLs, maxDepth)

		return ModuleWrapper{
			Module: crawler,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				if len(customURLs) > 0 {
					return crawler.Crawl(ctx)
				}
				return crawler.ScanCommonPages(ctx)
			},
		}, nil
	})
}
