package matrix

import "sync"

type KnowledgeGraph struct {
	mu              sync.RWMutex
	DiscoveredIPs   []string       `json:"discovered_ips"`
	OpenPorts       []int          `json:"open_ports"`
	DiscoveredURLs  []string       `json:"discovered_urls"`
	HarvestedTokens []string       `json:"harvested_tokens"`
	Vulnerabilities []string       `json:"vulnerabilities"`
	Context         map[string]any `json:"context"`
}

func NewKnowledgeGraph() *KnowledgeGraph {
	return &KnowledgeGraph{
		DiscoveredIPs:   make([]string, 0),
		OpenPorts:       make([]int, 0),
		DiscoveredURLs:  make([]string, 0),
		HarvestedTokens: make([]string, 0),
		Vulnerabilities: make([]string, 0),
		Context:         make(map[string]any),
	}
}

func (kg *KnowledgeGraph) AddIP(ip string) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.DiscoveredIPs {
		if existing == ip {
			return
		}
	}
	kg.DiscoveredIPs = append(kg.DiscoveredIPs, ip)
}

func (kg *KnowledgeGraph) AddPort(port int) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.OpenPorts {
		if existing == port {
			return
		}
	}
	kg.OpenPorts = append(kg.OpenPorts, port)
}

func (kg *KnowledgeGraph) AddURL(url string) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.DiscoveredURLs {
		if existing == url {
			return
		}
	}
	kg.DiscoveredURLs = append(kg.DiscoveredURLs, url)
}

func (kg *KnowledgeGraph) AddVulnerability(vuln string) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.Vulnerabilities {
		if existing == vuln {
			return
		}
	}
	kg.Vulnerabilities = append(kg.Vulnerabilities, vuln)
}

func (kg *KnowledgeGraph) AddToken(token string) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.HarvestedTokens {
		if existing == token {
			return
		}
	}
	kg.HarvestedTokens = append(kg.HarvestedTokens, token)
}
