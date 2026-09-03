package matrix

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// SiteNode represents a URL or path node in the Target Site Map
type SiteNode struct {
	Path        string              `json:"path"`
	Method      string              `json:"method,omitempty"`
	StatusCode  int                 `json:"status_code,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	Parameters  []string            `json:"parameters,omitempty"`
	Children    map[string]*SiteNode `json:"children,omitempty"`
	Discovered  time.Time           `json:"discovered"`
}

// SiteMap represents a tree structure of a target's web attack surface
type SiteMap struct {
	mu    sync.RWMutex
	Root  *SiteNode `json:"root"`
	Host  string    `json:"host"`
}

// NewSiteMap creates a new SiteMap for a given host
func NewSiteMap(host string) *SiteMap {
	return &SiteMap{
		Host: host,
		Root: &SiteNode{
			Path:     "/",
			Children: make(map[string]*SiteNode),
		},
	}
}

// AddURL parses a URL and inserts it into the SiteMap tree structure
func (sm *SiteMap) AddURL(rawURL string, method string, statusCode int, contentType string, params []string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme == "" && !strings.HasPrefix(rawURL, "/") && strings.Contains(rawURL, ".")) {
		if p, err2 := url.Parse("http://" + rawURL); err2 == nil {
			parsed = p
		} else if err != nil {
			return err
		}
	}

	// Auto-extract query parameters if not explicitly provided
	if len(params) == 0 && parsed.RawQuery != "" {
		for k := range parsed.Query() {
			params = append(params, k)
		}
		sort.Strings(params)
	}

	pathSegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	current := sm.Root

	for _, seg := range pathSegments {
		if seg == "" {
			continue
		}
		if current.Children == nil {
			current.Children = make(map[string]*SiteNode)
		}
		if _, exists := current.Children[seg]; !exists {
			current.Children[seg] = &SiteNode{
				Path:       seg,
				Children:   make(map[string]*SiteNode),
				Discovered: time.Now(),
			}
		}
		current = current.Children[seg]
	}

	// Update node metadata
	current.Method = method
	current.StatusCode = statusCode
	current.ContentType = contentType
	
	// Deduplicate parameters
	paramMap := make(map[string]bool)
	for _, p := range current.Parameters {
		paramMap[p] = true
	}
	for _, p := range params {
		if !paramMap[p] {
			current.Parameters = append(current.Parameters, p)
			paramMap[p] = true
		}
	}

	return nil
}

// SortedChildren returns the child nodes sorted alphabetically by path
func (sn *SiteNode) SortedChildren() []*SiteNode {
	if sn == nil || len(sn.Children) == 0 {
		return nil
	}
	keys := make([]string, 0, len(sn.Children))
	for k := range sn.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	children := make([]*SiteNode, 0, len(keys))
	for _, k := range keys {
		children = append(children, sn.Children[k])
	}
	return children
}

// NodeCount returns the total number of nodes in the site map
func (sm *SiteMap) NodeCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return countNodes(sm.Root)
}

func countNodes(node *SiteNode) int {
	if node == nil {
		return 0
	}
	count := 1
	for _, child := range node.Children {
		count += countNodes(child)
	}
	return count
}
