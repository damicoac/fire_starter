package core

import (
	"context"
	"fmt"
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

	var crawlNode func(currentURL string, depth int)
	crawlNode = func(currentURL string, depth int) {
		if ctx.Err() != nil {
			return
		}
		if depth > c.MaxDepth {
			return
		}

		mu.Lock()
		if visited[currentURL] || len(results) >= maxCrawledPages {
			mu.Unlock()
			return
		}
		visited[currentURL] = true
		mu.Unlock()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return
		}

		if c.BaseModule.Cookies != "" {
			req.Header.Set("Cookie", c.BaseModule.Cookies)
		}

		resp, err := c.Client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		// Ensure we record the successful page hit in the results
		mu.Lock()
		if !resultSet[currentURL] {
			resultSet[currentURL] = true
			results = append(results, currentURL)
		}
		mu.Unlock()

		tokenizer := html.NewTokenizer(resp.Body)
		var newLinks []string

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
						// Normalize by removing fragment
						parsedLink.Fragment = ""
						resolved := parsedLink.String()

						// Check scope and do not crawl binary media assets as HTML
						if parsedLink.Host == baseURL.Host {
							if isStaticAsset(resolved) {
								mu.Lock()
								if !resultSet[resolved] {
									resultSet[resolved] = true
									results = append(results, resolved)
								}
								mu.Unlock()
							} else {
								newLinks = append(newLinks, resolved)
							}
						}
					}
				}
			}
		}

		for _, link := range newLinks {
			crawlNode(link, depth+1)
		}
	}

	for _, startURL := range c.TargetURLs {
		crawlNode(startURL, 1)
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
				if len(PayloadString(payload, "urls", "")) > 0 {
					return crawler.Crawl(ctx)
				}
				return crawler.ScanCommonPages(ctx)
			},
		}, nil
	})
}
