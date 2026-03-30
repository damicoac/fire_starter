package modules

import (
	"net/url"
	"strings"
)

// APIDorkResult represents a generated API-focused search query and URL.
type APIDorkResult struct {
	Category  string `json:"category"`
	Query     string `json:"query"`
	SearchURL string `json:"search_url"`
}

// GoogleDorkingForAPIs generates targeted search queries for discovering API assets.
type GoogleDorkingForAPIs struct {
	Target string
}

// NewGoogleDorkingForAPIs creates a new API dorking generator.
func NewGoogleDorkingForAPIs(target string) *GoogleDorkingForAPIs {
	t := normalizeDorkTarget(target)
	return &GoogleDorkingForAPIs{Target: t}
}

// Generate builds a deduplicated set of API-focused dork queries and Google search URLs.
func (g *GoogleDorkingForAPIs) Generate() []APIDorkResult {
	domains := targetDomains(g.Target)
	if len(domains) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	results := make([]APIDorkResult, 0, len(domains)*8)

	for _, domain := range domains {
		patterns := []struct {
			category string
			query    string
		}{
			{category: "documentation", query: "site:" + domain + " (\"swagger\" OR \"openapi\" OR \"redoc\")"},
			{category: "versioned_paths", query: "site:" + domain + " (inurl:/api/v1/ OR inurl:/api/v2/ OR inurl:/v1/)"},
			{category: "index_listing", query: "site:" + domain + " intitle:\"index of\" (api OR swagger OR openapi)"},
			{category: "keys_and_tokens", query: "site:" + domain + " (\"api_key\" OR \"access_token\" OR \"x-api-key\")"},
			{category: "postman", query: "site:" + domain + " (inurl:postman OR \"postman_collection\")"},
			{category: "graphql", query: "site:" + domain + " (inurl:/graphql OR intitle:graphql)"},
			{category: "schema_files", query: "site:" + domain + " (filetype:json \"openapi\" OR filetype:yaml \"openapi\")"},
			{category: "test_and_legacy", query: "site:" + domain + " (inurl:staging/api OR inurl:dev/api OR inurl:test/api)"},
		}

		for _, p := range patterns {
			if seen[p.query] {
				continue
			}
			seen[p.query] = true
			results = append(results, APIDorkResult{
				Category:  p.category,
				Query:     p.query,
				SearchURL: "https://www.google.com/search?q=" + url.QueryEscape(p.query),
			})
		}
	}

	return results
}

func normalizeDorkTarget(target string) string {
	t := strings.TrimSpace(strings.ToLower(target))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "www.")
	if idx := strings.Index(t, "/"); idx >= 0 {
		t = t[:idx]
	}
	return strings.TrimSpace(t)
}

func targetDomains(target string) []string {
	t := normalizeDorkTarget(target)
	if t == "" {
		return nil
	}

	domains := []string{t}
	if strings.Count(t, ".") >= 1 {
		domains = append(domains, "*."+t)
	}
	return domains
}
