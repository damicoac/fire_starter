package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"
)

type TargetInfo struct {
	Value         string   `json:"value"`
	Score         int      `json:"score"`
	ExecutedTools []string `json:"executed_tools"`
}

type CredentialInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProofOfConcept struct {
	Description string `json:"description"`
	Request     string `json:"request"`
}

type TestCase struct {
	ToolName    string           `json:"tool_name"`
	Target      string           `json:"target"`
	Payload     string           `json:"payload"`
	ResultData  string           `json:"result_data"`
	Description string           `json:"description"`
	PoCs        []ProofOfConcept `json:"reproduction_steps,omitempty"`
}

type KnowledgeGraph struct {
	mu              sync.RWMutex
	BaseDomain      string           `json:"base_domain"`
	DiscoveredIPs   []TargetInfo     `json:"discovered_ips"`
	OpenPorts       map[string][]int `json:"open_ports"` // IP -> ports
	DiscoveredURLs   []TargetInfo      `json:"discovered_urls"`
	HarvestedTokens  []string          `json:"harvested_tokens"`
	Vulnerabilities  []string          `json:"vulnerabilities"`
	KnownCredentials []CredentialInfo  `json:"known_credentials"`
	TestCases        []TestCase        `json:"test_cases"`
	Context          map[string]any    `json:"context"`
	CurrentPhase     Phase             `json:"current_phase"`
	OnUpdate         func(*KnowledgeGraph) `json:"-"`
}

type KnowledgeSnapshot struct {
	DiscoveredIPCount   int
	DiscoveredURLCount  int
	OpenPortCount       int
	HarvestedTokenCount int
	VulnerabilityCount  int
	CurrentPhase        Phase
}

func NewKnowledgeGraph() *KnowledgeGraph {
	return &KnowledgeGraph{
		DiscoveredIPs:   make([]TargetInfo, 0),
		OpenPorts:       make(map[string][]int),
		DiscoveredURLs:   make([]TargetInfo, 0),
		HarvestedTokens:  make([]string, 0),
		Vulnerabilities:  make([]string, 0),
		KnownCredentials: make([]CredentialInfo, 0),
		TestCases:        make([]TestCase, 0),
		Context:          make(map[string]any),
		CurrentPhase:     PhaseReconnaissance,
	}
}

func (kg *KnowledgeGraph) triggerUpdate() {
	if kg.OnUpdate != nil {
		go kg.OnUpdate(kg)
	}
}

type ExtractedIntelligence struct {
	DiscoveredIPs   []string `json:"discovered_ips"`
	DiscoveredURLs  []string `json:"discovered_urls"`
	OpenPorts       []struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"open_ports"`
	HarvestedTokens []string         `json:"harvested_tokens"`
	Vulnerabilities []string         `json:"vulnerabilities"`
	Credentials     []CredentialInfo `json:"credentials"`
	Summary         string           `json:"summary"`
}

func (kg *KnowledgeGraph) ExtractIntelligence(ctx context.Context, model fantasy.LanguageModel, toolName, target string, payload map[string]any, resultData string) (string, error) {
	if model == nil {
		// Fallback for tests or missing model
		kg.regexExtract(toolName, target, payload, resultData)
		return "Regex extraction complete.", nil
	}

	truncatedResult := resultData
	if len(truncatedResult) > 30000 {
		truncatedResult = truncatedResult[:30000] + "... [TRUNCATED]"
	}

	prompt := fmt.Sprintf(`You are an intelligence extraction sub-agent.
Analyze the following tool output from '%s' against target '%s'.
Extract structured intelligence and provide a concise summary.

Respond STRICTLY in the following JSON format:
{
  "discovered_ips": ["list of IPs"],
  "discovered_urls": ["list of URLs"],
  "open_ports": [{"ip": "1.2.3.4", "port": 80}],
  "harvested_tokens": ["list of tokens/cookies"],
  "vulnerabilities": ["list of vulnerabilities"],
  "credentials": [{"username": "user", "password": "pw"}],
  "summary": "A concise 1-3 sentence summary of what the tool achieved and found."
}

Output:
%s`, toolName, target, truncatedResult)

	msg := fantasy.NewUserMessage(prompt)
	resp, err := model.Generate(ctx, fantasy.Call{
		Prompt: []fantasy.Message{msg},
	})
	if err != nil {
		return "", err
	}

	var rawText string
	for _, part := range resp.Content {
		if textPart, ok := part.(fantasy.TextContent); ok {
			rawText += textPart.Text
		}
	}

	rawText = strings.TrimSpace(rawText)
	if strings.HasPrefix(rawText, "```json") {
		rawText = strings.TrimPrefix(rawText, "```json")
		rawText = strings.TrimSuffix(rawText, "```")
	} else if strings.HasPrefix(rawText, "```") {
		rawText = strings.TrimPrefix(rawText, "```")
		rawText = strings.TrimSuffix(rawText, "```")
	}
	rawText = strings.TrimSpace(rawText)

	var extracted ExtractedIntelligence
	if err := json.Unmarshal([]byte(rawText), &extracted); err != nil {
		return "", fmt.Errorf("failed to parse sub-agent JSON: %w (raw output: %s)", err, rawText)
	}

	var parsedResult map[string]any
	var pocs []ProofOfConcept
	if err := json.Unmarshal([]byte(resultData), &parsedResult); err == nil {
		if steps, ok := parsedResult["reproduction_steps"]; ok {
			stepsBytes, _ := json.Marshal(steps)
			json.Unmarshal(stepsBytes, &pocs)
		}
	}

	for _, ip := range extracted.DiscoveredIPs {
		kg.AddIP(ip)
	}
	for _, u := range extracted.DiscoveredURLs {
		kg.AddURL(u)
	}
	for _, p := range extracted.OpenPorts {
		kg.AddPort(p.IP, p.Port)
	}
	for _, t := range extracted.HarvestedTokens {
		kg.AddToken(t)
	}
	for _, v := range extracted.Vulnerabilities {
		kg.AddVulnerability(v)
		
		payloadBytes, _ := json.Marshal(payload)
		kg.AddTestCase(TestCase{
			ToolName:    toolName,
			Target:      target,
			Payload:     string(payloadBytes),
			ResultData:  truncatedResult,
			Description: v,
			PoCs:        pocs,
		})
	}
	for _, c := range extracted.Credentials {
		kg.AddCredential(c.Username, c.Password)
	}

	return extracted.Summary, nil
}

func (kg *KnowledgeGraph) regexExtract(toolName, target string, payload map[string]any, resultData string) {
	var parsed any
	var pocs []ProofOfConcept
	if err := json.Unmarshal([]byte(resultData), &parsed); err == nil {
		if parsedMap, ok := parsed.(map[string]any); ok {
			if steps, ok := parsedMap["reproduction_steps"]; ok {
				stepsBytes, _ := json.Marshal(steps)
				json.Unmarshal(stepsBytes, &pocs)
			}
		}

		signalKeys := map[string]struct{}{
			"status":   {},
			"state":    {},
			"detail":   {},
			"message":  {},
			"evidence": {},
		}
		var inspect func(any)
		inspect = func(v any) {
			switch val := v.(type) {
			case map[string]any:
				for k, child := range val {
					key := strings.ToLower(strings.TrimSpace(k))
					childText := strings.ToLower(strings.TrimSpace(fmt.Sprint(child)))
					if _, ok := signalKeys[key]; ok {
						if strings.Contains(childText, "vulnerab") || strings.Contains(childText, "exploit") || strings.Contains(childText, "confirmed") {
							vulnDesc := "Vulnerability signal found: " + fmt.Sprint(child)
							kg.AddVulnerability(vulnDesc)
							
							payloadBytes, _ := json.Marshal(payload)
							truncatedResult := resultData
							if len(truncatedResult) > 30000 {
								truncatedResult = truncatedResult[:30000] + "... [TRUNCATED]"
							}
							kg.AddTestCase(TestCase{
								ToolName:    toolName,
								Target:      target,
								Payload:     string(payloadBytes),
								ResultData:  truncatedResult,
								Description: vulnDesc,
								PoCs:        pocs,
							})
						}
					}
					if key == "cookies" {
						switch cvals := child.(type) {
						case string:
							kg.AddToken(cvals)
						case []any:
							for _, c := range cvals {
								if cStr, ok := c.(string); ok {
									kg.AddToken(cStr)
								}
							}
						case []string:
							for _, c := range cvals {
								kg.AddToken(c)
							}
						}
					}
					inspect(child)
				}
			case []any:
				for _, child := range val {
					inspect(child)
				}
			}
		}
		inspect(parsed)
	}

	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	urlRegex := regexp.MustCompile(`https?://[^\s"']+`)

	ips := ipRegex.FindAllString(resultData, -1)
	for _, ip := range ips {
		kg.AddIP(ip)
	}

	urls := urlRegex.FindAllString(resultData, -1)
	for _, u := range urls {
		kg.AddURL(u)
	}

	if strings.Contains(strings.ToLower(resultData), "vulnerability") || strings.Contains(strings.ToLower(resultData), "exploited") {
		vulnDesc := "Generic Vulnerability Detected"
		kg.AddVulnerability(vulnDesc)
		
		payloadBytes, _ := json.Marshal(payload)
		truncatedResult := resultData
		if len(truncatedResult) > 30000 {
			truncatedResult = truncatedResult[:30000] + "... [TRUNCATED]"
		}
		kg.AddTestCase(TestCase{
			ToolName:    toolName,
			Target:      target,
			Payload:     string(payloadBytes),
			ResultData:  truncatedResult,
			Description: vulnDesc,
			PoCs:        pocs,
		})
	}
}

func (kg *KnowledgeGraph) ToJSON() ([]byte, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()
	return json.Marshal(kg)
}

func (kg *KnowledgeGraph) AddIP(ip string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for i, existing := range kg.DiscoveredIPs {
		if existing.Value == ip {
			kg.DiscoveredIPs[i].Score++
			return
		}
	}
	kg.DiscoveredIPs = append(kg.DiscoveredIPs, TargetInfo{Value: ip, Score: 1, ExecutedTools: make([]string, 0)})
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_ips value=%s score=1", ip)
}

func (kg *KnowledgeGraph) AddPort(ip string, port int) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	if _, ok := kg.OpenPorts[ip]; !ok {
		kg.OpenPorts[ip] = make([]int, 0)
	}
	for _, p := range kg.OpenPorts[ip] {
		if p == port {
			return
		}
	}
	kg.OpenPorts[ip] = append(kg.OpenPorts[ip], port)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=open_ports ip=%s port=%d", ip, port)

	for i, existing := range kg.DiscoveredIPs {
		if existing.Value == ip {
			kg.DiscoveredIPs[i].Score += 10
			break
		}
	}
}

func (kg *KnowledgeGraph) AddURL(u string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()

	u = strings.TrimSpace(u)
	u = strings.TrimRight(u, "/")
	if strings.HasPrefix(u, "www.") {
		u = strings.TrimPrefix(u, "www.")
	} else if strings.HasPrefix(u, "http://www.") {
		u = "http://" + strings.TrimPrefix(u, "http://www.")
	} else if strings.HasPrefix(u, "https://www.") {
		u = "https://" + strings.TrimPrefix(u, "https://www.")
	}

	if kg.BaseDomain != "" {
		parsed, err := url.Parse(u)
		if err != nil {
			return // Reject unparseable URLs
		}

		if parsed.Hostname() != "" {
			// Must match exact base domain or be a subdomain (e.g. .updater.com)
			host := parsed.Hostname()
			if host != kg.BaseDomain && !strings.HasSuffix(host, "."+kg.BaseDomain) {
				return // Reject URL outside of BaseDomain
			}
		} else if !strings.HasPrefix(u, "/") {
			// It might be a bare hostname like "test.updater.com"
			if p2, err2 := url.Parse("https://" + u); err2 == nil && p2.Hostname() != "" {
				host := p2.Hostname()
				if host != kg.BaseDomain && !strings.HasSuffix(host, "."+kg.BaseDomain) {
					return
				}
			}
		}

		path := strings.ToLower(parsed.Path)
		if strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") || 
		   strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") || 
		   strings.HasSuffix(path, ".jpeg") || strings.HasSuffix(path, ".svg") || 
		   strings.HasSuffix(path, ".gif") || strings.HasSuffix(path, ".woff") || 
		   strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ico") ||
		   strings.HasSuffix(path, ".ttf") || strings.HasSuffix(path, ".eot") {
			return // Reject static assets
		}
	}

	score := 1
	if strings.Contains(u, "?") || strings.Contains(u, "=") {
		score += 5
	}
	for i, existing := range kg.DiscoveredURLs {
		if existing.Value == u {
			kg.DiscoveredURLs[i].Score += score
			return
		}
	}
	kg.DiscoveredURLs = append(kg.DiscoveredURLs, TargetInfo{Value: u, Score: score, ExecutedTools: make([]string, 0)})
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_urls value=%s score=%d", u, score)
}

func (kg *KnowledgeGraph) AddVulnerability(vuln string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.Vulnerabilities {
		if existing == vuln {
			return
		}
	}
	kg.Vulnerabilities = append(kg.Vulnerabilities, vuln)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=vulnerabilities value=%s", vuln)
}

func (kg *KnowledgeGraph) AddTestCase(tc TestCase) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	kg.TestCases = append(kg.TestCases, tc)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=test_cases tool=%s target=%s", tc.ToolName, tc.Target)
}

func (kg *KnowledgeGraph) AddToken(token string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.HarvestedTokens {
		if existing == token {
			return
		}
	}
	kg.HarvestedTokens = append(kg.HarvestedTokens, token)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=harvested_tokens token_len=%d", len(token))
}

func (kg *KnowledgeGraph) AddCredential(username string, password string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	for _, existing := range kg.KnownCredentials {
		if existing.Username == username && existing.Password == password {
			return
		}
	}
	kg.KnownCredentials = append(kg.KnownCredentials, CredentialInfo{Username: username, Password: password})
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=known_credentials username=%s", username)
}

func (kg *KnowledgeGraph) GetCredentials() []CredentialInfo {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	credentials := make([]CredentialInfo, len(kg.KnownCredentials))
	copy(credentials, kg.KnownCredentials)
	return credentials
}

func (kg *KnowledgeGraph) SetContextValue(key string, value any) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	kg.Context[key] = value
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=context key=%s value=%v", key, value)
}

func (kg *KnowledgeGraph) SetCurrentPhase(phase Phase) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	previous := kg.CurrentPhase
	kg.CurrentPhase = phase
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=current_phase from=%s to=%s", previous, kg.CurrentPhase)
}

func (kg *KnowledgeGraph) AdvancePhase() Phase {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	previous := kg.CurrentPhase
	kg.CurrentPhase = NextPhase(kg.CurrentPhase)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=current_phase from=%s to=%s", previous, kg.CurrentPhase)
	return kg.CurrentPhase
}

func (kg *KnowledgeGraph) GetCurrentPhase() Phase {
	kg.mu.RLock()
	defer kg.mu.RUnlock()
	return kg.CurrentPhase
}

func (kg *KnowledgeGraph) GetTokens() []string {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	tokens := make([]string, len(kg.HarvestedTokens))
	copy(tokens, kg.HarvestedTokens)
	return tokens
}

func (kg *KnowledgeGraph) MarkToolExecuted(target string, toolName string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()

	markList := func(targets []TargetInfo) {
		for i := range targets {
			if targets[i].Value == target {
				found := false
				for _, t := range targets[i].ExecutedTools {
					if t == toolName {
						found = true
						break
					}
				}
				if !found {
					if targets[i].ExecutedTools == nil {
						targets[i].ExecutedTools = make([]string, 0)
					}
					targets[i].ExecutedTools = append(targets[i].ExecutedTools, toolName)
					log.Infof("KNOWLEDGE_GRAPH_UPDATE field=executed_tools target=%s tool=%s", target, toolName)
				}
			}
		}
	}

	markList(kg.DiscoveredIPs)
	markList(kg.DiscoveredURLs)
}

func (kg *KnowledgeGraph) Snapshot() KnowledgeSnapshot {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	openPortCount := 0
	for _, ports := range kg.OpenPorts {
		openPortCount += len(ports)
	}

	return KnowledgeSnapshot{
		DiscoveredIPCount:   len(kg.DiscoveredIPs),
		DiscoveredURLCount:  len(kg.DiscoveredURLs),
		OpenPortCount:       openPortCount,
		HarvestedTokenCount: len(kg.HarvestedTokens),
		VulnerabilityCount:  len(kg.Vulnerabilities),
		CurrentPhase:        kg.CurrentPhase,
	}
}
