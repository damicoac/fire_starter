package matrix

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"
	"golang.org/x/net/publicsuffix"
)

// GenerateVulnID generates a deterministic hash for a vulnerability based on its target and description.
func GenerateVulnID(target, finding string) string {
	normalizedTarget := NormalizeURL(target)
	trimmedFinding := strings.TrimSpace(finding)
	hash := md5.Sum([]byte(normalizedTarget + trimmedFinding))
	return hex.EncodeToString(hash[:])
}

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
	if idx := strings.Index(u, "#"); idx != -1 {
		u = u[:idx]
	}
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

		firstSeg := u
		if idx := strings.Index(u, "/"); idx != -1 {
			firstSeg = u[:idx]
		}

		if baseURL != nil {
			if strings.HasPrefix(u, baseURL.Host+"/") || u == baseURL.Host {
				isAbsoluteSchemeless = true
			} else if strings.HasSuffix(firstSeg, "."+baseURL.Host) {
				isAbsoluteSchemeless = true
			}
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
	VulnID      string           `json:"vuln_id"`
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
	CurrentPhase    Phase            `json:"current_phase"`
	ExecutedTools   []string         `json:"executed_tools"`
	OpenPorts       []int            `json:"open_ports,omitempty"`
	Tokens          []string         `json:"tokens,omitempty"`
	Vulnerabilities []string         `json:"vulnerabilities,omitempty"`
	Credentials     []CredentialInfo `json:"credentials,omitempty"`
	TestCases       []TestCase       `json:"test_cases,omitempty"`
	HTTPRequestGate map[string]bool `json:"http_request_gate,omitempty"`
	urlSignals      map[string]bool
}

type KnowledgeGraph struct {
	mu             sync.RWMutex
	BaseDomain     string                      `json:"base_domain"`
	TargetDomains  []string                    `json:"target_domains"`
	allowedIPs     map[string]bool
	ConfigTarget   string                      `json:"config_target"`
	Targets        map[string]*Target          `json:"targets"`
	SessionCookies map[string][]*http.Cookie   `json:"session_cookies"`
	Context        map[string]any              `json:"context"`
	OnUpdate       func(*KnowledgeGraph)       `json:"-"`
	updateChan     chan struct{}               `json:"-"`
}

type KnowledgeSnapshot struct {
	DiscoveredIPCount   int
	DiscoveredURLCount  int
	OpenPortCount       int
	HarvestedTokenCount int
	VulnerabilityCount  int
	TargetPhases        map[string]Phase
	OpenPorts           []int
}

func NewKnowledgeGraph() *KnowledgeGraph {
	kg := &KnowledgeGraph{
		Targets:        make(map[string]*Target),
		SessionCookies: make(map[string][]*http.Cookie),
		Context:        make(map[string]any),
		TargetDomains:  make([]string, 0),
		allowedIPs:     make(map[string]bool),
		updateChan:     make(chan struct{}, 1),
	}
	go func() {
		for range kg.updateChan {
			if kg.OnUpdate != nil {
				kg.OnUpdate(kg)
			}
		}
	}()
	return kg
}

func (kg *KnowledgeGraph) triggerUpdate() {
	select {
	case kg.updateChan <- struct{}{}:
	default:
	}
}

func (kg *KnowledgeGraph) RLock() {
	kg.mu.RLock()
}

func (kg *KnowledgeGraph) RUnlock() {
	kg.mu.RUnlock()
}

func (kg *KnowledgeGraph) Lock() {
	kg.mu.Lock()
}

func (kg *KnowledgeGraph) Unlock() {
	kg.mu.Unlock()
}

func IsZeroTarget(val string) bool {
	if val == "0.0.0.0" || val == "::" || val == "[::]" {
		return true
	}
	if strings.HasPrefix(val, "0.0.0.0:") || strings.HasPrefix(val, "0.0.0.0/") {
		return true
	}
	if strings.HasPrefix(val, "::/") || strings.HasPrefix(val, "[::]:") || strings.HasPrefix(val, "[::]/") {
		return true
	}
	if strings.HasPrefix(val, "http://0.0.0.0") || strings.HasPrefix(val, "https://0.0.0.0") ||
		strings.HasPrefix(val, "http://[::]") || strings.HasPrefix(val, "https://[::]") {
		return true
	}
	return false
}

func (kg *KnowledgeGraph) getOrCreateTarget(value string, targetType string) *Target {
	value = NormalizeURL(value)
	if IsZeroTarget(value) {
		return nil
	}
	if kg.Targets[value] == nil {
		score := 0
		if kg.ConfigTarget != "" && NormalizeURL(kg.ConfigTarget) == value {
			score = 25
		}
		kg.Targets[value] = &Target{
			Value:           value,
			Type:            targetType,
			Score:           score,
			CurrentPhase:    PhaseReconnaissance,
			ExecutedTools:   make([]string, 0),
			OpenPorts:       make([]int, 0),
			Tokens:          make([]string, 0),
			Vulnerabilities: make([]string, 0),
			Credentials:     make([]CredentialInfo, 0),
			TestCases:       make([]TestCase, 0),
			HTTPRequestGate: make(map[string]bool),
			urlSignals:      make(map[string]bool),
		}
	}
	return kg.Targets[value]
}

type ExtractedToken struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
}

type ExtractedIntelligence struct {
	DiscoveredIPs   []string `json:"discovered_ips"`
	DiscoveredURLs  []string `json:"discovered_urls"`
	OpenPorts       []struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"open_ports"`
	HarvestedTokens []ExtractedToken `json:"harvested_tokens"`
	Vulnerabilities []string         `json:"vulnerabilities"`
	Credentials     []CredentialInfo `json:"credentials"`
	Summary         string           `json:"summary"`
}

func (kg *KnowledgeGraph) evaluateScopeWithLLM(ctx context.Context, model fantasy.LanguageModel, ips []string, urls []string) ([]string, []string) {
	if len(ips) == 0 && len(urls) == 0 {
		return nil, nil
	}

	fallbackAllowedIPs, fallbackAllowedURLs := kg.filterCandidatesByScope(ips, urls)

	domains := kg.TargetDomains
	if len(domains) == 0 && kg.BaseDomain != "" {
		domains = []string{kg.BaseDomain}
	}

	// If no whitelist targets are configured at all, allow everything
	if len(domains) == 0 {
		return ips, urls
	}

	candidates := append([]string{}, ips...)
	candidates = append(candidates, urls...)

	type DecisionItem struct {
		Candidate string `json:"candidate"`
		ShouldAdd bool   `json:"should_add"`
		Reason    string `json:"reason"`
	}
	type BatchDecision struct {
		Results []DecisionItem `json:"results"`
	}

	prompt := fmt.Sprintf(`You are a security boundary guard sub-agent.
Your task is to evaluate a list of candidate IPs and URLs/domains discovered during a red team engagement, and decide if they are related to the whitelisted targets.
We must ONLY target/add systems that are in-scope and related.

Whitelisted Targets:
%s

Candidate Targets to Evaluate:
%s

For each candidate, decide if it should be added to the knowledge graph (should_add = true) or ignored (should_add = false).
Rules for deciding:
1. Subdomains of a whitelisted domain are related and should be added.
2. IPs that belong to the whitelisted domains or configured target networks are related.
3. Common third-party domains (e.g. googleapis.com, jquery.com, cloudflare.com, bootstrapcdn.com) or external CDNs/apis should NOT be added.
4. Unrelated IPs should NOT be added.
5. Provide a clear, concise reason explaining your decision.

Respond STRICTLY in the following JSON format:
{
  "results": [
    {
      "candidate": "candidate name",
      "should_add": true,
      "reason": "explanation of relationship or lack thereof"
    }
  ]
}`, strings.Join(domains, ", "), strings.Join(candidates, "\n"))

	msg := fantasy.NewUserMessage(prompt)
	resp, err := model.Generate(ctx, fantasy.Call{
		Prompt: []fantasy.Message{msg},
	})
	if err != nil {
		log.Errorf("Decision agent failed to generate: %v. Falling back to default whitelisting check.", err)
		return fallbackAllowedIPs, fallbackAllowedURLs
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

	var decision BatchDecision
	if err := json.Unmarshal([]byte(rawText), &decision); err != nil {
		log.Errorf("Decision agent returned invalid JSON: %v. Falling back to default whitelisting check.", err)
		return fallbackAllowedIPs, fallbackAllowedURLs
	}

	shouldAddMap := make(map[string]bool)
	for _, item := range decision.Results {
		shouldAddMap[item.Candidate] = item.ShouldAdd
		log.Debugf("DECISION_TO_ADD candidate=%s should_add=%v reason=%s", item.Candidate, item.ShouldAdd, item.Reason)
	}

	var allowedIPs []string
	var allowedURLs []string
	for _, ip := range ips {
		if val, exists := shouldAddMap[ip]; exists {
			if val {
				allowedIPs = append(allowedIPs, ip)
			}
		} else {
			// If not returned by LLM, default to false (safe approach)
			log.Warnf("Decision agent omitted candidate IP: %s. Defaulting to ignore.", ip)
		}
	}
	for _, u := range urls {
		if val, exists := shouldAddMap[u]; exists {
			if val {
				allowedURLs = append(allowedURLs, u)
			}
		} else {
			// If not returned by LLM, default to false
			log.Warnf("Decision agent omitted candidate URL: %s. Defaulting to ignore.", u)
		}
	}

	return allowedIPs, allowedURLs
}

func (kg *KnowledgeGraph) ExtractIntelligence(ctx context.Context, model fantasy.LanguageModel, toolName, target string, payload map[string]any, resultData string) (string, string, error) {
	if model == nil {
		kg.regexExtract(toolName, target, payload, resultData)
		return "Regex extraction complete.", "{}", nil
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
  "harvested_tokens": [{"session_id": "name_of_role_or_user", "token": "the_cookie_or_token"}],
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
		return "", "", err
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
		return "", "", fmt.Errorf("failed to parse sub-agent JSON: %w (raw output: %s)", err, rawText)
	}

	var parsedResult map[string]any
	var pocs []ProofOfConcept
	if err := json.Unmarshal([]byte(resultData), &parsedResult); err == nil {
		if steps, ok := parsedResult["reproduction_steps"]; ok {
			stepsBytes, _ := json.Marshal(steps)
			json.Unmarshal(stepsBytes, &pocs)
		}
	}

	allowedIPs, allowedURLs := kg.evaluateScopeWithLLM(ctx, model, extracted.DiscoveredIPs, extracted.DiscoveredURLs)

	for _, ip := range allowedIPs {
		kg.AddIP(ip)
	}
	for _, u := range allowedURLs {
		kg.AddURL(u, target)
	}
	for _, p := range extracted.OpenPorts {
		kg.AddPort(p.IP, p.Port)
	}
	for _, t := range extracted.HarvestedTokens {
		kg.AddToken(target, t.SessionID, t.Token)
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
	if len(allowedURLs) > 0 {
		summary += "\n\nDiscovered URLs: " + strings.Join(allowedURLs, ", ")
	}
	if len(allowedIPs) > 0 {
		summary += "\n\nDiscovered IPs: " + strings.Join(allowedIPs, ", ")
	}
	return summary, rawText, nil
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
							kg.AddToken(target, "default", cvals)
						case []any:
							for _, c := range cvals {
								if cStr, ok := c.(string); ok {
									kg.AddToken(target, "default", cStr)
								}
							}
						case []string:
							for _, c := range cvals {
								kg.AddToken(target, "default", c)
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
	urlRegex := regexp.MustCompile(`(?i)(?:https?://|www\.)[^\s"'<>]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s"'<>]*)?|/(?:[a-z0-9._~!$&'()*+,;=:@%-]+/?)+`)

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
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return strings.ToLower(base)
}

func MatchDomainOrIP(input string, pattern string) bool {
	input = strings.ToLower(strings.TrimSpace(input))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	if pattern == "" || input == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		if base == "" {
			return false
		}
		if input == base {
			return true
		}
		if strings.HasSuffix(input, "."+base) {
			return true
		}
		return registrableDomain(input) == base
	}

	if strings.Contains(pattern, "*") {
		matched, err := filepath.Match(pattern, input)
		return err == nil && matched
	}

	return input == pattern
}

func (kg *KnowledgeGraph) filterCandidatesByScope(ips []string, urls []string) ([]string, []string) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	domains := kg.TargetDomains
	if len(domains) == 0 && kg.BaseDomain != "" {
		domains = []string{kg.BaseDomain}
	}

	if len(domains) == 0 {
		allowedIPs := append([]string(nil), ips...)
		allowedURLs := append([]string(nil), urls...)
		return allowedIPs, allowedURLs
	}

	allowedIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if kg.ipAllowedByScopeLocked(ip, domains) {
			allowedIPs = append(allowedIPs, ip)
		}
	}

	allowedURLs := make([]string, 0, len(urls))
	for _, candidateURL := range urls {
		if kg.urlAllowedByScopeLocked(candidateURL, domains) {
			allowedURLs = append(allowedURLs, candidateURL)
		}
	}

	return allowedIPs, allowedURLs
}

func (kg *KnowledgeGraph) ipAllowedByScopeLocked(ip string, domains []string) bool {
	for _, pattern := range domains {
		if pattern == "*" || MatchDomainOrIP(ip, pattern) {
			return true
		}
	}
	return kg.allowedIPs != nil && kg.allowedIPs[ip]
}

func (kg *KnowledgeGraph) urlAllowedByScopeLocked(candidateURL string, domains []string) bool {
	normalized := ResolveAndNormalizeURL(candidateURL, "")
	if normalized == "" {
		return false
	}

	parsed, err := url.Parse("https://" + normalized)
	if err != nil || parsed.Hostname() == "" {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	for _, pattern := range domains {
		if MatchDomainOrIP(host, pattern) {
			return true
		}
	}

	return false
}

func (kg *KnowledgeGraph) AddAllowedIP(ip string) {
	kg.mu.Lock()
	defer kg.mu.Unlock()
	if kg.allowedIPs == nil {
		kg.allowedIPs = make(map[string]bool)
	}
	kg.allowedIPs[ip] = true
}

func (kg *KnowledgeGraph) ToJSON(target string) ([]byte, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	targetsCopy := make(map[string]*Target)
	for k, v := range kg.Targets {
		tCopy := *v
		if target != "" && NormalizeURL(k) != NormalizeURL(target) {
			tCopy.Tokens = nil // Omit tokens and cookies for other targets
		}
		targetsCopy[k] = &tCopy
	}

	type KGWrapper struct {
		BaseDomain     string             `json:"base_domain"`
		TargetDomains  []string           `json:"target_domains"`
		ConfigTarget   string             `json:"config_target"`
		Targets        map[string]*Target `json:"targets"`
		SessionCookies map[string][]*http.Cookie `json:"session_cookies"`
		Context        map[string]any     `json:"context"`
	}

	wrapper := KGWrapper{
		BaseDomain:     kg.BaseDomain,
		TargetDomains:  kg.TargetDomains,
		ConfigTarget:   kg.ConfigTarget,
		Targets:        targetsCopy,
		SessionCookies: kg.SessionCookies,
		Context:        kg.Context,
	}

	return json.Marshal(wrapper)
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

	// 1. Check if allowed by IP whitelist if it is configured
	var ipWhitelist []string
	if val, ok := kg.Context["ip_whitelist"]; ok {
		if slice, ok := val.([]string); ok {
			ipWhitelist = slice
		} else if slice, ok := val.([]any); ok {
			for _, item := range slice {
				if s, ok := item.(string); ok {
					ipWhitelist = append(ipWhitelist, s)
				}
			}
		}
	}

	if len(ipWhitelist) > 0 {
		allowed := false
		for _, wIP := range ipWhitelist {
			if wIP == ip {
				allowed = true
				break
			}
		}
		if !allowed {
			return
		}
	}

	// 2. Check if allowed by TargetDomains
	domains := kg.TargetDomains
	if len(domains) == 0 && kg.BaseDomain != "" {
		domains = []string{kg.BaseDomain}
	}

	if len(domains) > 0 {
		allowedByDomainOrIP := false
		for _, pattern := range domains {
			if pattern == "*" {
				allowedByDomainOrIP = true
				break
			}
			if MatchDomainOrIP(ip, pattern) {
				allowedByDomainOrIP = true
				break
			}
		}
		if !allowedByDomainOrIP && kg.allowedIPs != nil && kg.allowedIPs[ip] {
			allowedByDomainOrIP = true
		}
		if !allowedByDomainOrIP {
			return
		}
	}

	t := kg.getOrCreateTarget(ip, "ip")
	if t == nil {
		return
	}
	t.Score++
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_ips value=%s score=%d", ip, t.Score)
}

func (kg *KnowledgeGraph) AddPort(targetValue string, port int) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(targetValue, "ip") // ports imply an IP mostly, or URL
	if t == nil {
		return
	}
	
	for _, p := range t.OpenPorts {
		if p == port {
			return
		}
	}
	t.OpenPorts = append(t.OpenPorts, port)
	t.Score += 10
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=open_ports target=%s port=%d", targetValue, port)
}

func isStaticAssetPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	return strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".jpeg") || strings.HasSuffix(path, ".svg") ||
		strings.HasSuffix(path, ".gif") || strings.HasSuffix(path, ".woff") ||
		strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".ttf") || strings.HasSuffix(path, ".eot")
}

func (kg *KnowledgeGraph) AddURL(u string, baseCtx string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()

	hasQuerySignal := strings.Contains(u, "?") || strings.Contains(u, "=")
	score := 1
	if hasQuerySignal {
		score += 5
	}

	u = ResolveAndNormalizeURL(u, baseCtx)
	if u == "" {
		return
	}

	parsed, err := url.Parse("https://" + u)
	if err != nil || parsed.Hostname() == "" {
		return
	}

	if isStaticAssetPath(parsed.Path) {
		return
	}

	domains := kg.TargetDomains
	if len(domains) == 0 && kg.BaseDomain != "" {
		domains = []string{kg.BaseDomain}
	}

	host := strings.ToLower(parsed.Hostname())
	if len(domains) > 0 {
		matched := false
		for _, pattern := range domains {
			if MatchDomainOrIP(host, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return
		}

		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			allPlaceholder := true
			for _, ip := range ips {
				if ip.String() != "0.0.0.0" && ip.String() != "::" && !ip.IsLoopback() {
					allPlaceholder = false
					if kg.allowedIPs == nil {
						kg.allowedIPs = make(map[string]bool)
					}
					kg.allowedIPs[ip.String()] = true
				}
			}
			if allPlaceholder {
				return
			}
		}
	}

	t := kg.getOrCreateTarget(u, "url")
	if t == nil {
		return
	}
	if t.urlSignals == nil {
		t.urlSignals = make(map[string]bool)
	}
	signalKey := fmt.Sprintf("path=%s|query=%t", parsed.Path, hasQuerySignal)
	if t.urlSignals[signalKey] {
		return
	}
	t.urlSignals[signalKey] = true
	t.Score += score
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=discovered_urls value=%s score=%d", u, t.Score)
}

func (kg *KnowledgeGraph) AddVulnerability(targetValue string, vuln string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	t := kg.getOrCreateTarget(targetValue, "url") // default to url, though could be IP
	if t == nil {
		return
	}
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
	if t == nil {
		return
	}

	if tc.VulnID == "" {
		tc.VulnID = GenerateVulnID(tc.Target, tc.Description)
	}

	t.TestCases = append(t.TestCases, tc)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=test_cases target=%s tool=%s vuln_id=%s", tc.Target, tc.ToolName, tc.VulnID)

	// Format test_code: prioritize PoC requests, fallback to tool payload JSON
	var testCode string
	if len(tc.PoCs) > 0 {
		var pocParts []string
		for _, poc := range tc.PoCs {
			if poc.Request != "" {
				pocParts = append(pocParts, fmt.Sprintf("%s\n%s", poc.Description, poc.Request))
			} else {
				pocParts = append(pocParts, poc.Description)
			}
		}
		testCode = strings.Join(pocParts, "\n\n")
	} else {
		testCode = tc.Payload
	}

	if t.CurrentPhase == PhaseReconnaissance || t.CurrentPhase == PhaseScanning || t.CurrentPhase == PhaseVulnerabilityAnalysis {
		if err := LogVulnerability(tc.VulnID, NormalizeURL(tc.Target), tc.Description, testCode, "no", "no"); err != nil {
			log.Warnf("Failed to log vulnerability to database: %v", err)
		}
	}
}

func parseCookieStr(s string, defaultDomain string) *http.Cookie {
	c := &http.Cookie{Path: "/"}
	s = strings.TrimPrefix(s, "Cookie:")
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if i == 0 {
			kv := strings.SplitN(part, "=", 2)
			c.Name = strings.TrimSpace(kv[0])
			if len(kv) > 1 {
				c.Value = strings.TrimSpace(kv[1])
			}
		} else {
			kv := strings.SplitN(part, "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := ""
			if len(kv) > 1 {
				val = strings.TrimSpace(kv[1])
			}
			switch key {
			case "domain":
				c.Domain = val
			case "path":
				c.Path = val
			case "httponly":
				c.HttpOnly = true
			case "secure":
				c.Secure = true
			}
		}
	}
	if c.Domain == "" && defaultDomain != "" {
		if u, err := url.Parse(defaultDomain); err == nil && u.Hostname() != "" {
			c.Domain = u.Hostname()
		} else if !strings.HasPrefix(defaultDomain, "http") {
			if u, err := url.Parse("https://" + defaultDomain); err == nil && u.Hostname() != "" {
				c.Domain = u.Hostname()
			} else {
				c.Domain = defaultDomain
			}
		}
	}
	return c
}

func (kg *KnowledgeGraph) AddToken(targetValue string, sessionID string, token string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	if sessionID == "" {
		sessionID = "default"
	}
	
	t := kg.getOrCreateTarget(targetValue, "url")
	if t == nil {
		return
	}

	c := parseCookieStr(token, targetValue)
	
	if kg.SessionCookies == nil {
		kg.SessionCookies = make(map[string][]*http.Cookie)
	}
	
	for _, existing := range kg.SessionCookies[sessionID] {
		if existing.Name == c.Name && existing.Value == c.Value {
			return // already exists
		}
	}
	
	kg.SessionCookies[sessionID] = append(kg.SessionCookies[sessionID], c)
	
	for _, existing := range t.Tokens {
		if existing == token {
			return
		}
	}
	t.Tokens = append(t.Tokens, token)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=harvested_tokens target=%s session=%s token_len=%d", targetValue, sessionID, len(token))
}

func (kg *KnowledgeGraph) AddCredential(targetValue string, username string, password string) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	
	// Create or get the target for credential storage. 
	// If it's a completely generic credential (e.g. baseline), we could use a dummy target.
	// But usually they belong to something.
	t := kg.getOrCreateTarget(targetValue, "url")
	if t == nil {
		return
	}
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

func (kg *KnowledgeGraph) GetTargetPhase(targetValue string) Phase {
	kg.mu.RLock()
	defer kg.mu.RUnlock()
	t, ok := kg.Targets[targetValue]
	if !ok {
		return PhaseReconnaissance
	}
	return t.CurrentPhase
}

func (kg *KnowledgeGraph) AdvanceTargetPhase(targetValue string) Phase {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	t, ok := kg.Targets[targetValue]
	if !ok {
		return PhaseReconnaissance
	}
	previous := t.CurrentPhase
	t.CurrentPhase = NextPhase(t.CurrentPhase)
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=target_phase target=%s from=%s to=%s", targetValue, previous, t.CurrentPhase)
	return t.CurrentPhase
}

func (kg *KnowledgeGraph) SetTargetPhase(targetValue string, phase Phase) {
	defer kg.triggerUpdate()
	kg.mu.Lock()
	defer kg.mu.Unlock()
	t, ok := kg.Targets[targetValue]
	if !ok {
		return
	}
	previous := t.CurrentPhase
	t.CurrentPhase = phase
	log.Infof("KNOWLEDGE_GRAPH_UPDATE field=target_phase target=%s from=%s to=%s", targetValue, previous, t.CurrentPhase)
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
	if t == nil {
		return
	}
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

	var allPorts []int
	targetPhases := make(map[string]Phase)

	for _, t := range kg.Targets {
		if t.Type == "ip" {
			ipCount++
		} else {
			urlCount++
		}
		portCount += len(t.OpenPorts)
		allPorts = append(allPorts, t.OpenPorts...)
		tokenCount += len(t.Tokens)
		vulnCount += len(t.Vulnerabilities)
		targetPhases[t.Value] = t.CurrentPhase
	}

	return KnowledgeSnapshot{
		DiscoveredIPCount:   ipCount,
		DiscoveredURLCount:  urlCount,
		OpenPortCount:       portCount,
		HarvestedTokenCount: tokenCount,
		VulnerabilityCount:  vulnCount,
		TargetPhases:        targetPhases,
		OpenPorts:           allPorts,
	}
}

func getHostOfNormalizedTarget(target string) string {
	target = strings.TrimSpace(target)
	if idx := strings.Index(target, "/"); idx != -1 {
		return target[:idx]
	}
	return target
}

func getHostnameOfNormalizedTarget(target string) string {
	host := getHostOfNormalizedTarget(target)
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}

func isDomainOrSubdomain(host, parentDomain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	parentDomain = strings.ToLower(strings.TrimSpace(parentDomain))
	if host == parentDomain {
		return true
	}
	// IPs must match exactly
	if net.ParseIP(host) != nil || net.ParseIP(parentDomain) != nil {
		return host == parentDomain
	}
	return strings.HasSuffix(host, "."+parentDomain)
}

func (kg *KnowledgeGraph) GetCookiesForRequest(sessionID string, targetURL string) string {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	if kg.SessionCookies == nil || len(kg.SessionCookies[sessionID]) == 0 {
		return ""
	}
	
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	
	reqHost := parsedURL.Hostname()
	reqPath := parsedURL.Path
	if reqPath == "" {
		reqPath = "/"
	}

	var validCookies []string
	for _, cookie := range kg.SessionCookies[sessionID] {
		// Domain match
		domainMatch := false
		if cookie.Domain == "" {
			domainMatch = true // Assume valid if no domain set
		} else {
			domainMatch = isDomainOrSubdomain(reqHost, cookie.Domain) || isDomainOrSubdomain(cookie.Domain, reqHost)
		}
		
		// Path match
		pathMatch := false
		if cookie.Path == "" || cookie.Path == "/" {
			pathMatch = true
		} else {
			pathMatch = strings.HasPrefix(reqPath, cookie.Path)
		}
		
		if domainMatch && pathMatch {
			validCookies = append(validCookies, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
		}
	}
	
	return strings.Join(validCookies, "; ")
}

func (kg *KnowledgeGraph) GetTokensForTarget(targetValue string) []string {
	cookiesStr := kg.GetCookiesForRequest("default", targetValue)
	if cookiesStr == "" {
		return nil
	}
	return strings.Split(cookiesStr, "; ")
}

