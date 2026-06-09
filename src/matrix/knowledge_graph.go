package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"
)

func NormalizeURL(u string) string {
	u = strings.TrimSpace(u)
	lower := strings.ToLower(u)
	if strings.HasPrefix(lower, "http://") {
		u = u[7:]
	} else if strings.HasPrefix(lower, "https://") {
		u = u[8:]
	}
	lower = strings.ToLower(u)
	if strings.HasPrefix(lower, "www.") {
		u = u[4:]
	}
	// Strip fragment
	if idx := strings.Index(u, "#"); idx != -1 {
		u = u[:idx]
	}
	// Strip query parameters
	if idx := strings.Index(u, "?"); idx != -1 {
		u = u[:idx]
	}
	u = strings.TrimRight(u, "/")
	
	slashIdx := strings.Index(u, "/")
	if slashIdx != -1 {
		u = strings.ToLower(u[:slashIdx]) + u[slashIdx:]
	} else {
		u = strings.ToLower(u)
	}
	return u
}

func ResolveAndNormalizeURL(u string, baseCtx string) string {
	u = strings.TrimSpace(u)
	baseCtx = strings.TrimSpace(baseCtx)

	if u == "" {
		return ""
	}

	var baseURL *url.URL
	if baseCtx != "" {
		if !strings.HasPrefix(baseCtx, "http://") && !strings.HasPrefix(baseCtx, "https://") {
			parsed, err := url.Parse("http://" + baseCtx)
			if err == nil {
				baseURL = parsed
			}
		} else {
			parsed, err := url.Parse(baseCtx)
			if err == nil {
				baseURL = parsed
			}
		}
	}

	hasScheme := strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
	if !hasScheme {
		isAbsoluteSchemeless := false

		if baseURL != nil {
			if strings.HasPrefix(u, baseURL.Host+"/") || u == baseURL.Host {
				isAbsoluteSchemeless = true
			}
		}
		
		firstSeg := u
		if idx := strings.Index(u, "/"); idx != -1 {
			firstSeg = u[:idx]
		}
		if net.ParseIP(firstSeg) != nil || (strings.Contains(firstSeg, ":") && net.ParseIP(strings.Split(firstSeg, ":")[0]) != nil) {
			isAbsoluteSchemeless = true
		} else if strings.Contains(firstSeg, ".") {
			if baseURL == nil {
				isAbsoluteSchemeless = true
			}
		}

		if isAbsoluteSchemeless {
			u = "http://" + u
			hasScheme = true
		}
	}

	if baseURL != nil && !hasScheme {
		refURL, err := url.Parse(u)
		if err == nil {
			resolved := baseURL.ResolveReference(refURL)
			u = resolved.String()
		}
	}

	return NormalizeURL(u)
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

type Target struct {
	Value           string           `json:"value"`
	Type            string           `json:"type"` // "ip" or "url"
	Score           int              `json:"score"`
	ExecutedTools   []string         `json:"executed_tools"`
	OpenPorts       []int            `json:"open_ports,omitempty"`
	Tokens          []string         `json:"tokens,omitempty"`
	Vulnerabilities []string         `json:"vulnerabilities,omitempty"`
	Credentials     []CredentialInfo `json:"credentials,omitempty"`
	TestCases       []TestCase       `json:"test_cases,omitempty"`
}

type KnowledgeGraph struct {
	mu           sync.RWMutex
	BaseDomain   string             `json:"base_domain"`
	Targets      map[string]*Target `json:"targets"`
	Context      map[string]any     `json:"context"`
	CurrentPhase Phase              `json:"current_phase"`
	OnUpdate     func(*KnowledgeGraph) `json:"-"`
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
		Targets:      make(map[string]*Target),
		Context:      make(map[string]any),
		CurrentPhase: PhaseReconnaissance,
	}
}

func (kg *KnowledgeGraph) triggerUpdate() {
	if kg.OnUpdate != nil {
		go kg.OnUpdate(kg)
	}
}

func (kg *KnowledgeGraph) getOrCreateTarget(value string, targetType string) *Target {
	if targetType == "url" {
		value = NormalizeURL(value)
	}
	if kg.Targets[value] == nil {
		kg.Targets[value] = &Target{
			Value:           value,
			Type:            targetType,
			Score:           0,
			ExecutedTools:   make([]string, 0),
			OpenPorts:       make([]int, 0),
			Tokens:          make([]string, 0),
			Vulnerabilities: make([]string, 0),
			Credentials:     make([]CredentialInfo, 0),
			TestCases:       make([]TestCase, 0),
		}
	}
	return kg.Targets[value]
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
  "vulnerabilities": ["list of vulnerabilities (Provide descriptions only. DO NOT include reproduction steps or curl commands here. They are automatically extracted.)"],
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
		kg.AddURL(u, target)
	}
	for _, p := range extracted.OpenPorts {
		kg.AddPort(p.IP, p.Port)
	}
	for _, t := range extracted.HarvestedTokens {
		kg.AddToken(target, t)
	}
	for _, v := range extracted.Vulnerabilities {
		kg.AddVulnerability(target, v)
		
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
		kg.AddCredential(target, c.Username, c.Password)
	}

	summary := extracted.Summary
	if len(extracted.DiscoveredURLs) > 0 {
		summary += "\n\nDiscovered URLs: " + strings.Join(extracted.DiscoveredURLs, ", ")
	}
	if len(extracted.DiscoveredIPs) > 0 {
		summary += "\n\nDiscovered IPs: " + strings.Join(extracted.DiscoveredIPs, ", ")
	}
	return summary, nil
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
							kg.AddVulnerability(target, vulnDesc)
							
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
							kg.AddToken(target, cvals)
						case []any:
							for _, c := range cvals {
								if cStr, ok := c.(string); ok {
									kg.AddToken(target, cStr)
								}
							}
						case []string:
							for _, c := range cvals {
								kg.AddToken(target, c)
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
		kg.AddURL(u, target)
	}

	if strings.Contains(strings.ToLower(resultData), "vulnerability") || strings.Contains(strings.ToLower(resultData), "exploited") {
		vulnDesc := "Generic Vulnerability Detected"
		kg.AddVulnerability(target, vulnDesc)
		
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
	if ip == "0.0.0.0" || ip == "::" {
		return
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		return
	}
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(ip, "ip")
	t.Score++
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_ips value=%s score=%d", ip, t.Score)
}

func (kg *KnowledgeGraph) AddPort(targetValue string, port int) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(targetValue, "ip") // ports imply an IP mostly, or URL
	
	for _, p := range t.OpenPorts {
		if p == port {
			return
		}
	}
	t.OpenPorts = append(t.OpenPorts, port)
	t.Score += 10
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=open_ports target=%s port=%d", targetValue, port)
}

func (kg *KnowledgeGraph) AddURL(u string, baseCtx string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()

	score := 1
	if strings.Contains(u, "?") || strings.Contains(u, "=") {
		score += 5
	}

	u = ResolveAndNormalizeURL(u, baseCtx)

	if kg.BaseDomain != "" {
		parsed, err := url.Parse("https://" + u)
		if err != nil {
			return
		}

		if parsed.Hostname() != "" {
			host := parsed.Hostname()
			if host != kg.BaseDomain && !strings.HasSuffix(host, "."+kg.BaseDomain) {
				return
			}

			if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
				allPlaceholder := true
				for _, ip := range ips {
					if ip.String() != "0.0.0.0" && ip.String() != "::" && !ip.IsLoopback() {
						allPlaceholder = false
						break
					}
				}
				if allPlaceholder {
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
			return
		}
	}

	t := kg.getOrCreateTarget(u, "url")
	t.Score += score
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_urls value=%s score=%d", u, t.Score)
}

func (kg *KnowledgeGraph) AddVulnerability(targetValue string, vuln string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(targetValue, "url") // default to url, though could be IP
	for _, existing := range t.Vulnerabilities {
		if existing == vuln {
			return
		}
	}
	t.Vulnerabilities = append(t.Vulnerabilities, vuln)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=vulnerabilities target=%s value=%s", targetValue, vuln)
}

func (kg *KnowledgeGraph) AddTestCase(tc TestCase) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(tc.Target, "url")
	t.TestCases = append(t.TestCases, tc)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=test_cases target=%s tool=%s", tc.Target, tc.ToolName)
}

func (kg *KnowledgeGraph) AddToken(targetValue string, token string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(targetValue, "url")
	for _, existing := range t.Tokens {
		if existing == token {
			return
		}
	}
	t.Tokens = append(t.Tokens, token)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=harvested_tokens target=%s token_len=%d", targetValue, len(token))
}

func (kg *KnowledgeGraph) AddCredential(targetValue string, username string, password string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	// Create or get the target for credential storage. 
	// If it's a completely generic credential (e.g. baseline), we could use a dummy target.
	// But usually they belong to something.
	t := kg.getOrCreateTarget(targetValue, "url")
	for _, existing := range t.Credentials {
		if existing.Username == username && existing.Password == password {
			return
		}
	}
	t.Credentials = append(t.Credentials, CredentialInfo{Username: username, Password: password})
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=known_credentials target=%s username=%s", targetValue, username)
}

func (kg *KnowledgeGraph) GetCredentials() []CredentialInfo {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	var credentials []CredentialInfo
	for _, t := range kg.Targets {
		credentials = append(credentials, t.Credentials...)
	}
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

	var tokens []string
	for _, t := range kg.Targets {
		tokens = append(tokens, t.Tokens...)
	}
	return tokens
}

func (kg *KnowledgeGraph) MarkToolExecuted(target string, toolName string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()

	t := kg.getOrCreateTarget(target, "url") // Assume url as generic type or leave it
	found := false
	for _, tool := range t.ExecutedTools {
		if tool == toolName {
			found = true
			break
		}
	}
	if !found {
		t.ExecutedTools = append(t.ExecutedTools, toolName)
		log.Infof("KNOWLEDGE_GRAPH_UPDATE field=executed_tools target=%s tool=%s", target, toolName)
	}
}

func (kg *KnowledgeGraph) Snapshot() KnowledgeSnapshot {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	ipCount := 0
	urlCount := 0
	portCount := 0
	tokenCount := 0
	vulnCount := 0

	for _, t := range kg.Targets {
		if t.Type == "ip" {
			ipCount++
		} else {
			urlCount++
		}
		portCount += len(t.OpenPorts)
		tokenCount += len(t.Tokens)
		vulnCount += len(t.Vulnerabilities)
	}

	return KnowledgeSnapshot{
		DiscoveredIPCount:   ipCount,
		DiscoveredURLCount:  urlCount,
		OpenPortCount:       portCount,
		HarvestedTokenCount: tokenCount,
		VulnerabilityCount:  vulnCount,
		CurrentPhase:        kg.CurrentPhase,
	}
}
