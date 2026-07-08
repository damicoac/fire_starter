package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"charm.land/fantasy"
	"charm.land/fantasy/providers/anthropic"
	"charm.land/fantasy/providers/google"
	"charm.land/fantasy/providers/openai"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
)

func initializeModel(ctx context.Context, cfg Config) (fantasy.LanguageModel, error) {
	var provider fantasy.Provider
	var err error

	switch strings.ToLower(cfg.Provider) {
	case "openai", "local", "ollama":
		var opts []openai.Option
		if cfg.BaseURL != "" {
			opts = append(opts, openai.WithBaseURL(normalizeBaseURL(cfg.Provider, cfg.BaseURL)))
		}
		provider, err = openai.New(opts...)
	case "anthropic":
		provider, err = anthropic.New()
	case "gemini", "google":
		provider, err = google.New()
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to init provider %s: %w", cfg.Provider, err)
	}

	return provider.LanguageModel(ctx, cfg.Model)
}

type scoredTool struct {
	Definition matrix.ToolDefinition
	Score      int
	Reasons    []string
}

type httpRequestGateState struct {
	hasExecuted           bool
	lastTargetFingerprint string
	lastAuthFingerprint   string
}

func normalizeTarget(t string) string {
	return matrix.NormalizeURL(t)
}

func joinSortedStrings(values []string) string {
	if len(values) == 0 {
		return ""
	}

	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return strings.Join(copyValues, ",")
}

func joinSortedInts(values []int) string {
	if len(values) == 0 {
		return ""
	}

	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	parts := make([]string, 0, len(copyValues))
	for _, value := range copyValues {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func credentialSignalFingerprint(credentials []matrix.CredentialInfo) string {
	if len(credentials) == 0 {
		return ""
	}

	signals := make(map[string]bool)
	for _, credential := range credentials {
		username := strings.ToLower(strings.TrimSpace(credential.Username))
		if username == "" {
			username = "<blank>"
		}
		signals[username] = true
	}

	parts := make([]string, 0, len(signals))
	for signal := range signals {
		parts = append(parts, signal)
	}
	return joinSortedStrings(parts)
}

func tokenSignalFingerprint(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}

	signals := make(map[string]bool)
	for _, token := range tokens {
		trimmed := strings.TrimSpace(token)
		if trimmed == "" {
			continue
		}
		if name, _, ok := strings.Cut(trimmed, "="); ok {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				signals["cookie:"+name] = true
				continue
			}
		}

		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "bearer "):
			signals["bearer"] = true
		case strings.Count(trimmed, ".") == 2:
			signals["jwt"] = true
		default:
			signals["opaque"] = true
		}
	}

	parts := make([]string, 0, len(signals))
	for signal := range signals {
		parts = append(parts, signal)
	}
	return joinSortedStrings(parts)
}

func httpRequestTargetFingerprint(target *matrix.Target) string {
	if target == nil {
		return ""
	}

	return fmt.Sprintf(
		"target=%s|phase=%s|ports=%s|vulns=%s",
		normalizeTarget(target.Value),
		target.CurrentPhase,
		joinSortedInts(target.OpenPorts),
		joinSortedStrings(target.Vulnerabilities),
	)
}

func httpRequestAuthFingerprint(target *matrix.Target) string {
	if target == nil {
		return ""
	}

	return fmt.Sprintf(
		"token_signals=%s|credential_signals=%s",
		tokenSignalFingerprint(target.Tokens),
		credentialSignalFingerprint(target.Credentials),
	)
}

func authReopenGateKey(targetFingerprint string, authFingerprint string) string {
	return targetFingerprint + "|" + authFingerprint
}

func updateHTTPRequestGateState(state *httpRequestGateState, target *matrix.Target) {
	if state == nil || target == nil {
		return
	}

	state.hasExecuted = true
	state.lastTargetFingerprint = httpRequestTargetFingerprint(target)
	state.lastAuthFingerprint = httpRequestAuthFingerprint(target)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasPort(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}

func scoreTool(def matrix.ToolDefinition, target *matrix.Target, snapshot matrix.KnowledgeSnapshot, httpRequestState *httpRequestGateState) scoredTool {
	stage := matrix.Phase(matrix.MapTechniqueToStage(def.Technique))
	score := 0
	reasons := make([]string, 0, 4)

	for _, exec := range target.ExecutedTools {
		if exec == def.Name {
			if def.Name != "decision_http_request" {
				return scoredTool{Definition: def, Score: -100, Reasons: []string{"already executed on this target"}}
			}
		}
	}

	if def.Name == "decision_http_request" {
		targetFingerprint := httpRequestTargetFingerprint(target)
		authFingerprint := httpRequestAuthFingerprint(target)
		switch {
		case httpRequestState == nil || !httpRequestState.hasExecuted:
			score += 50
			reasons = append(reasons, "http_request allowed for initial target probe")
		case targetFingerprint != httpRequestState.lastTargetFingerprint:
			score += 35
			reasons = append(reasons, "target intelligence unlocked another http_request")
		case authFingerprint != httpRequestState.lastAuthFingerprint:
			gateKey := authReopenGateKey(targetFingerprint, authFingerprint)
			if target.HTTPRequestGate != nil && target.HTTPRequestGate[gateKey] {
				return scoredTool{Definition: def, Score: -100, Reasons: []string{"authenticated follow-up already used for this target state"}}
			}
			score += 20
			reasons = append(reasons, "one authenticated follow-up allowed for the current target state")
		default:
			return scoredTool{Definition: def, Score: -100, Reasons: []string{"no new target intelligence since last http_request"}}
		}
	}

	switch {
	case stage == target.CurrentPhase:
		score += 10
		reasons = append(reasons, "matches target phase")
	case stage == matrix.PhaseReconnaissance:
		score += 3
		reasons = append(reasons, "always-recon exception")
	}

	name := strings.ToLower(def.Name)
	if strings.Contains(name, "ssh") && hasPort(target.OpenPorts, 22) {
		score += 3
		reasons = append(reasons, "ssh port 22 is open")
	}
	if (strings.Contains(name, "sql") || strings.Contains(name, "database") || strings.Contains(name, "db")) && (hasPort(target.OpenPorts, 3306) || hasPort(target.OpenPorts, 5432)) {
		score += 3
		reasons = append(reasons, "database port is open")
	}
	if strings.Contains(name, "ftp") && hasPort(target.OpenPorts, 21) {
		score += 3
		reasons = append(reasons, "ftp port 21 is open")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "baseline")
	}

	return scoredTool{Definition: def, Score: score, Reasons: reasons}
}

func canCompleteTarget(snapshot matrix.KnowledgeSnapshot, target string, efficiencyMode bool) (bool, string) {
	phase, ok := snapshot.TargetPhases[target]
	if !ok {
		return false, "target not found in snapshot"
	}

	if phase == matrix.PhaseReporting {
		return true, "target exhausted"
	}

	if efficiencyMode {
		return true, "efficiency mode enabled, target can be skipped or exited early"
	}

	if snapshot.VulnerabilityCount == 0 {
		if phase != matrix.PhaseReconnaissance {
			return true, "no vulnerabilities found and target completed recon, early exit allowed"
		}
		return false, "no vulnerabilities found, but target must complete recon before early exit"
	}

	return false, "vulnerabilities found globally; must exhaust target before completing"
}

func summarizeSnapshot(snapshot matrix.KnowledgeSnapshot) string {
	return fmt.Sprintf("ips=%d urls=%d open_ports=%d vulnerabilities=%d tokens=%d targets=%d",
		snapshot.DiscoveredIPCount,
		snapshot.DiscoveredURLCount,
		snapshot.OpenPortCount,
		snapshot.VulnerabilityCount,
		snapshot.HarvestedTokenCount,
		len(snapshot.TargetPhases),
	)
}

func reachedIterationLimit(globalIters int, maxIters int) bool {
	return maxIters > 0 && globalIters >= maxIters
}

func snapshotDelta(before, after matrix.KnowledgeSnapshot) string {
	changes := make([]string, 0, 5)
	if after.DiscoveredIPCount > before.DiscoveredIPCount {
		changes = append(changes, fmt.Sprintf("ips:+%d", after.DiscoveredIPCount-before.DiscoveredIPCount))
	}
	if after.DiscoveredURLCount > before.DiscoveredURLCount {
		changes = append(changes, fmt.Sprintf("urls:+%d", after.DiscoveredURLCount-before.DiscoveredURLCount))
	}
	if after.OpenPortCount > before.OpenPortCount {
		changes = append(changes, fmt.Sprintf("open_ports:+%d", after.OpenPortCount-before.OpenPortCount))
	}
	if after.VulnerabilityCount > before.VulnerabilityCount {
		changes = append(changes, fmt.Sprintf("vulnerabilities:+%d", after.VulnerabilityCount-before.VulnerabilityCount))
	}
	if after.HarvestedTokenCount > before.HarvestedTokenCount {
		changes = append(changes, fmt.Sprintf("tokens:+%d", after.HarvestedTokenCount-before.HarvestedTokenCount))
	}
	if len(changes) == 0 {
		return "no_new_intelligence"
	}
	return strings.Join(changes, ",")
}

func recommendedNextAction(canCompleteNow bool, reason string) string {
	if canCompleteNow {
		return "target_completed (" + reason + ")"
	}
	return "continue_execution"
}

func normalizeBaseURL(provider string, baseURL string) string {
	if baseURL == "" {
		return ""
	}

	trimmed := strings.TrimRight(baseURL, "/")
	switch strings.ToLower(provider) {
	case "local", "ollama":
		if strings.HasSuffix(trimmed, "/v1") {
			return trimmed
		}
		return trimmed + "/v1"
	default:
		return baseURL
	}
}

func extractIPsFromTarget(target string) []string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil
	}
	parsed := strings.TrimSpace(trimmed)
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			parsed = u.Hostname()
		}
	}
	if ip := net.ParseIP(parsed); ip != nil {
		if ip.String() == "0.0.0.0" || ip.String() == "::" {
			return nil
		}
		return []string{ip.String()}
	}
	ips, err := net.LookupIP(parsed)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if s == "0.0.0.0" || s == "::" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func deriveDefaultTargetDomains(target string) []string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil
	}

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return nil
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return nil
	}
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return []string{host}
	}

	return []string{host, "*." + host}
}

func allowlistedIPsSummary(allowlist map[string]bool) string {
	if len(allowlist) == 0 {
		return "none"
	}
	ips := make([]string, 0, len(allowlist))
	for ip := range allowlist {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return strings.Join(ips, ", ")
}

func isPayloadAllowedByIPWhitelist(payload map[string]any, allowlist map[string]bool) bool {
	if len(allowlist) == 0 {
		return true
	}
	collect := func(value any, out map[string]bool) {
		switch v := value.(type) {
		case string:
			parsed := strings.TrimSpace(v)
			if parsed == "" {
				return
			}
			if strings.Contains(parsed, "://") {
				if u, err := url.Parse(parsed); err == nil {
					parsed = u.Hostname()
				}
			}
			if ip := net.ParseIP(parsed); ip != nil {
				s := ip.String()
				if s != "0.0.0.0" && s != "::" {
					out[s] = true
				}
			} else {
				ips, err := net.LookupIP(parsed)
				if err == nil {
					for _, ip := range ips {
						s := ip.String()
						if s != "0.0.0.0" && s != "::" {
							out[s] = true
						}
					}
				}
			}
		}
	}

	ips := make(map[string]bool)
	collect(payload["ip"], ips)
	collect(payload["target"], ips)
	collect(payload["url"], ips)
	if nested, ok := payload["payload"].(map[string]any); ok {
		collect(nested["ip"], ips)
		collect(nested["target"], ips)
		collect(nested["url"], ips)
	}
	if len(ips) == 0 {
		return false
	}
	for ip := range ips {
		if !allowlist[ip] {
			return false
		}
	}
	return true
}

func requiresCredentialValidation(finding string) bool {
	lowerFinding := strings.ToLower(strings.TrimSpace(finding))
	if lowerFinding == "" {
		return false
	}
	if strings.Contains(lowerFinding, ".env") {
		return true
	}
	credentialLeakIndicators := []string{"credential", "password", "username", "token", "secret", "api key", "apikey", "session"}
	for _, indicator := range credentialLeakIndicators {
		if strings.Contains(lowerFinding, indicator) {
			if strings.Contains(lowerFinding, "leak") || strings.Contains(lowerFinding, "exposed") || strings.Contains(lowerFinding, "public") || strings.Contains(lowerFinding, "disclos") {
				return true
			}
		}
	}
	return false
}

func credentialUseEvidenceInTestCode(testCode string) bool {
	lowerTestCode := strings.ToLower(strings.TrimSpace(testCode))
	if lowerTestCode == "" {
		return false
	}
	hasCredentialAttempt := strings.Contains(lowerTestCode, "login") || strings.Contains(lowerTestCode, "auth") || strings.Contains(lowerTestCode, "credential") || strings.Contains(lowerTestCode, "username") || strings.Contains(lowerTestCode, "password") || strings.Contains(lowerTestCode, "session")
	hasSuccessEvidence := strings.Contains(lowerTestCode, "authenticated") || strings.Contains(lowerTestCode, "logged in") || strings.Contains(lowerTestCode, "success") || strings.Contains(lowerTestCode, "valid") || strings.Contains(lowerTestCode, "200") || strings.Contains(lowerTestCode, "token issued")
	return hasCredentialAttempt && hasSuccessEvidence
}

func validateVulnerabilityLogInput(vulnID string, target string, finding string, testCode string, exploitable string) error {
	if strings.TrimSpace(vulnID) == "" || strings.TrimSpace(target) == "" || strings.TrimSpace(finding) == "" || strings.TrimSpace(testCode) == "" || (exploitable != "yes" && exploitable != "no") {
		return fmt.Errorf("vuln_id, target, finding, test_code, and exploitable ('yes'|'no') are required")
	}
	if exploitable == "yes" && requiresCredentialValidation(finding) && !credentialUseEvidenceInTestCode(testCode) {
		return fmt.Errorf("credential leaks cannot be marked exploitable='yes' without evidence of a successful credential-based authentication attempt in test_code")
	}
	return nil
}

func collectHelperVulnQueue(currentTarget string, kg *matrix.KnowledgeGraph) []matrix.VulnInfo {
	queue := make([]matrix.VulnInfo, 0)
	seen := make(map[string]bool)
	normalizedTarget := normalizeTarget(currentTarget)

	processedFindings := make(map[string]bool)
	if vulns, err := matrix.GetVulnerabilities(); err == nil {
		for _, v := range vulns {
			if normalizeTarget(v.TargetDomain) == normalizedTarget {
				if strings.EqualFold(v.Processed, "yes") {
					processedFindings[strings.TrimSpace(v.Finding)] = true
				}
			}
		}
	}

	kg.RLock()
	if t, ok := kg.Targets[normalizedTarget]; ok {
		for _, finding := range t.Vulnerabilities {
			trimmed := strings.TrimSpace(finding)
			if trimmed != "" && !seen[trimmed] && !processedFindings[trimmed] {
				seen[trimmed] = true
				
				// Generate a consistent vuln_id hash
				vid := matrix.GenerateVulnID(normalizedTarget, trimmed)
				
				queue = append(queue, matrix.VulnInfo{Finding: trimmed, VulnID: vid})
			}
		}
	}
	kg.RUnlock()

	if vulns, err := matrix.GetVulnerabilities(); err == nil {
		for _, v := range vulns {
			if normalizeTarget(v.TargetDomain) != normalizedTarget {
				continue
			}
			if strings.EqualFold(v.Processed, "no") {
				trimmed := strings.TrimSpace(v.Finding)
				if trimmed != "" && !seen[trimmed] && !processedFindings[trimmed] {
					seen[trimmed] = true
					queue = append(queue, v)
				}
			}
		}
	}

	return queue
}

func runVulnerabilityHelperSubAgent(
	ctx context.Context,
	model fantasy.LanguageModel,
	currentTarget string,
	finding string,
	origVulnID string,
	activeTools []fantasy.Tool,
	kg *matrix.KnowledgeGraph,
	executor *matrix.RealExecutor,
	initialTarget string,
	allowlist map[string]bool,
	toolStageByName map[string]matrix.Phase,
) string {
	var rawGraph []byte
	if rawBytes, err := kg.ToJSON(currentTarget); err == nil {
		var data map[string]any
		if err := json.Unmarshal(rawBytes, &data); err == nil {
			// Strip test cases from targets to reduce prompt bloat
			if targets, ok := data["targets"].(map[string]any); ok {
				for _, tgt := range targets {
					if tgtMap, ok := tgt.(map[string]any); ok {
						delete(tgtMap, "test_cases")
					}
				}
			}
			rawGraph, _ = json.Marshal(data)
		} else {
			rawGraph = rawBytes
		}
	}
	prompt := fmt.Sprintf("You are a vulnerability helper sub-agent. Focus only on target '%s' and finding '%s' (vuln_id: %s). Use the available tools to validate exploitability and refine proof-of-concept evidence. DO NOT write your own custom tools or scripts; you must use the provided tools for testing. If confirmed, call log_vulnerability with vuln_id, target, finding, exploitable yes/no and include concise test_code. Make sure the 'finding' parameter contains a detailed description of how the vulnerability works and step-by-step instructions to recreate it. For exposed credentials (e.g. .env leaks), do not set exploitable='yes' unless you successfully authenticate using the leaked credentials and include that evidence in test_code. If not enough evidence, propose the next exact test.", currentTarget, finding, origVulnID)

	history := []fantasy.Message{
		{Role: "system", Content: []fantasy.MessagePart{fantasy.TextPart{Text: "You are a focused vulnerability helper sub-agent. DO NOT write your own custom tools or scripts; you must use the provided tools for testing."}}},
		fantasy.NewUserMessage(prompt + "\n\nKnowledge Graph Snapshot:\n" + string(rawGraph)),
	}

	var out strings.Builder
	vulnLogged := false
	executedPayloads := make(map[string]bool)

	for turn := 0; turn < 5; turn++ {
		resp, err := model.Generate(ctx, fantasy.Call{
			Prompt: history,
			Tools:  activeTools,
		})
		if err != nil {
			log.Errorf("Helper LLM error: %v", err)
			break
		}

		assistantMsg := fantasy.Message{Role: "assistant"}
		var textParts []string
		for _, c := range resp.Content {
			switch v := c.(type) {
			case fantasy.TextContent:
				if strings.TrimSpace(v.Text) != "" {
					textParts = append(textParts, v.Text)
					assistantMsg.Content = append(assistantMsg.Content, fantasy.TextPart{Text: v.Text})
				}
			case fantasy.ToolCallContent:
				assistantMsg.Content = append(assistantMsg.Content, fantasy.ToolCallPart{
					ToolCallID: v.ToolCallID,
					ToolName:   v.ToolName,
					Input:      v.Input,
				})
			}
		}
		history = append(history, assistantMsg)

		toolCalls := resp.Content.ToolCalls()
		if len(toolCalls) == 0 {
			for _, t := range textParts {
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				out.WriteString(t)
			}
			break
		}

		var toolResultParts []fantasy.MessagePart
		for _, tc := range toolCalls {
			log.Infof("Helper tool call: %s", tc.ToolName)
			if tc.ToolName == "log_vulnerability" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Invalid JSON input."},
					})
					continue
				}
				_, _ = args["vuln_id"].(string)
				targetStr, _ := args["target"].(string)
				fnd, _ := args["finding"].(string)
				testCode, _ := args["test_code"].(string)
				exploitable, _ := args["exploitable"].(string)

				// Update the existing vulnerability record keeping the ID the same
				if validationErr := validateVulnerabilityLogInput(origVulnID, targetStr, fnd, testCode, exploitable); validationErr != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: %v", validationErr)},
					})
					continue
				}
				normalizedTgt := normalizeTarget(targetStr)
				if err := matrix.LogVulnerability(origVulnID, normalizedTgt, fnd, testCode, exploitable, "yes"); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: failed to log vulnerability: %v", err)},
					})
					continue
				}
				
				vulnLogged = true
				
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "Vulnerability logged and marked processed."},
				})
				continue
			}

			if tc.ToolName == "query_knowledge_graph" {
				var qArgs map[string]any
				_ = json.Unmarshal([]byte(tc.Input), &qArgs)
				qType, _ := qArgs["query_type"].(string)

				var resBytes []byte
				switch qType {
				case "ips":
					var ips []string
					for _, t := range kg.Targets {
						if t.Type == "ip" {
							ips = append(ips, t.Value)
						}
					}
					resBytes, _ = json.Marshal(ips)
				case "urls":
					var urls []string
					for _, t := range kg.Targets {
						if t.Type == "url" {
							urls = append(urls, t.Value)
						}
					}
					resBytes, _ = json.Marshal(urls)
				case "ports":
					ports := make(map[string][]int)
					for _, t := range kg.Targets {
						if len(t.OpenPorts) > 0 {
							ports[t.Value] = t.OpenPorts
						}
					}
					resBytes, _ = json.Marshal(ports)
				case "credentials":
					resBytes, _ = json.Marshal(kg.GetCredentials())
				case "vulnerabilities":
					vulns, err := matrix.GetVulnerabilities()
					if err != nil {
						resBytes, _ = json.Marshal(map[string]string{"error": fmt.Sprintf("failed to query vulnerabilities: %v", err)})
					} else {
						resBytes, _ = json.Marshal(vulns)
					}
				case "tokens":
					resBytes, _ = json.Marshal(kg.GetTokens())
				default:
					rawBytes, _ := kg.ToJSON(currentTarget)
					var data map[string]any
					if err := json.Unmarshal(rawBytes, &data); err == nil {
						// Strip test cases from targets to reduce prompt bloat
						if targets, ok := data["targets"].(map[string]any); ok {
							for _, tgt := range targets {
								if tgtMap, ok := tgt.(map[string]any); ok {
									delete(tgtMap, "test_cases")
								}
							}
						}
						resBytes, _ = json.Marshal(data)
					} else {
						resBytes = rawBytes
					}
				}

				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: string(resBytes)},
				})
				continue
			}

			if tc.ToolName == "advance_target_phase" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err == nil {
					if tStr, ok := args["target"].(string); ok && tStr != "" {
						normalizedTarget := normalizeTarget(tStr)
						newPhase := kg.AdvanceTargetPhase(normalizedTarget)
						toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
							ToolCallID: tc.ToolCallID,
							Output:     fantasy.ToolResultOutputContentText{Text: "Target advanced to next phase successfully."},
						})
						log.Infof("Helper advanced target phase: target=%s new_phase=%s", tStr, newPhase)
					} else {
						toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
							ToolCallID: tc.ToolCallID,
							Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Missing target."},
						})
					}
				} else {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Invalid JSON input."},
					})
				}
				continue
			}

			if tc.ToolName == "target_completed" {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: helper sub-agent cannot complete the orchestrator target."},
				})
				continue
			}

			var args map[string]any
			if tc.Input != "" {
				if err := json.Unmarshal([]byte(tc.Input), &args); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: Failed to parse tool input JSON: %v", err)},
					})
					continue
				}
			}

			payload := make(map[string]any)
			if nested, ok := args["payload"].(map[string]any); ok {
				for k, v := range nested {
					payload[k] = v
				}
			}
			for k, v := range args {
				if k != "payload" {
					payload[k] = v
				}
			}

			if len(allowlist) > 0 && !isPayloadAllowedByIPWhitelist(payload, allowlist) {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: blocked by IP whitelist policy. Allowed IPs: " + allowlistedIPsSummary(allowlist)},
				})
				continue
			}

			payloadBytes, _ := json.Marshal(payload)
			payloadHash := fmt.Sprintf("%s|%s", tc.ToolName, string(payloadBytes))
			if executedPayloads[payloadHash] {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: You have already successfully executed this tool with this exact payload in this helper run. Choose different parameters or another tool."},
				})
				continue
			}

			targetUsed := initialTarget
			if tStr, ok := payload["target"].(string); ok && strings.TrimSpace(tStr) != "" {
				targetUsed = strings.TrimSpace(tStr)
			} else if uStr, ok := payload["url"].(string); ok && strings.TrimSpace(uStr) != "" {
				targetUsed = strings.TrimSpace(uStr)
			} else if ipStr, ok := payload["ip"].(string); ok && strings.TrimSpace(ipStr) != "" {
				targetUsed = strings.TrimSpace(ipStr)
			}

			sessionID, hasSession := args["session_id"].(string)
			var sessionsToTest []string
			if hasSession && sessionID != "" {
				sessionsToTest = []string{sessionID}
			} else {
				sessionsToTest = []string{"unauthenticated", "default"}
			}

			var allSummaries []string
			var res string

			for _, sess := range sessionsToTest {
				iterPayload := make(map[string]any)
				for k, v := range payload {
					iterPayload[k] = v
				}

				if sess != "unauthenticated" {
					cookiesStr := kg.GetCookiesForRequest(sess, targetUsed)
					if cookiesStr != "" {
						iterPayload["cookies"] = cookiesStr
					}
					if _, hasUsername := iterPayload["username"]; !hasUsername {
						credentials := kg.GetCredentials()
						if len(credentials) > 0 {
							iterPayload["username"] = credentials[0].Username
							iterPayload["password"] = credentials[0].Password
						}
					}
				} else {
					iterPayload["cookies"] = ""
				}

				resultData, execErr := executor.ExecuteByToolName(tc.ToolName, iterPayload, func(s string) {
					log.Debug(s)
				})

				if execErr != nil {
					errStr := fmt.Sprintf("TOOL_ERROR (Session: %s): %v", sess, execErr)
					allSummaries = append(allSummaries, errStr)
					log.Debugf("Helper tool execution failed: tool=%s session=%s error=%s", tc.ToolName, sess, errStr)
				} else {
					executedPayloads[payloadHash] = true
					if t, ok := iterPayload["target"].(string); ok && strings.TrimSpace(t) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(t), tc.ToolName)
					}
					if u, ok := iterPayload["url"].(string); ok && strings.TrimSpace(u) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(u), tc.ToolName)
					}
					if ip, ok := iterPayload["ip"].(string); ok && strings.TrimSpace(ip) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(ip), tc.ToolName)
					}

					summary, _, extractErr := kg.ExtractIntelligence(ctx, model, tc.ToolName, targetUsed, iterPayload, resultData)
					if extractErr != nil {
						log.Warnf("Helper intelligence extraction failed: %v", extractErr)
						summary = fmt.Sprintf("Tool executed successfully but intelligence extraction failed: %v", extractErr)
					}

					if err := matrix.LogExecution(initialTarget, resultData); err != nil {
						log.Warnf("Failed to log execution to SQLite: %v", err)
					}

					log.Infof("Helper tool execution success: tool=%s session=%s summary=%q", tc.ToolName, sess, summary)
					allSummaries = append(allSummaries, fmt.Sprintf("[Session: %s] %s", sess, summary))
				}
			}

			res = fmt.Sprintf("=== TOOL EXECUTION SUMMARY ===\n%s", strings.Join(allSummaries, "\n\n"))

			toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
				ToolCallID: tc.ToolCallID,
				Output:     fantasy.ToolResultOutputContentText{Text: res},
			})
		}

		history = append(history, fantasy.Message{
			Role:    "tool",
			Content: toolResultParts,
		})

		for _, t := range textParts {
			if out.Len() > 0 {
				out.WriteString("\n")
			}
			out.WriteString(t)
		}
	}

	if !vulnLogged {
		log.Infof("Helper exhausted iterations without logging, marking exploitable=no for vuln_id=%s", origVulnID)
		_ = matrix.LogVulnerability(origVulnID, currentTarget, finding, "", "no", "yes")
	}

	return out.String()
}

func RunAgent(ctx context.Context, target string, cfg Config, onKGUpdate func(*matrix.KnowledgeGraph)) (string, error) {
	model, err := initializeModel(ctx, cfg)
	if err != nil {
		return "", err
	}

	decisionsFile := "src/matrix/decisions.json"
	bytes, err := matrix.ReadDecisionsFile(decisionsFile)
	if err != nil {
		return "", fmt.Errorf("failed to read decisions.json: %w", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return "", fmt.Errorf("error parsing decisions JSON: %w", err)
	}

	executor, err := matrix.NewRealExecutor(data.Decisions)
	if err != nil {
		return "", fmt.Errorf("failed to init executor: %w", err)
	}
	kg := matrix.NewKnowledgeGraph()
	kg.ConfigTarget = target
	kg.OnUpdate = onKGUpdate

	if _, err := matrix.InitDB("fire_starter.db"); err != nil {
		log.Warnf("Failed to init SQLite database: %v", err)
	}

	// Populate TargetDomains whitelist from config
	if len(cfg.TargetDomains) > 0 {
		kg.TargetDomains = cfg.TargetDomains
	} else {
		kg.TargetDomains = deriveDefaultTargetDomains(target)
	}

	// For backwards compatibility, set BaseDomain to the first target domain
	if len(kg.TargetDomains) > 0 {
		first := kg.TargetDomains[0]
		if strings.HasPrefix(first, "*.") {
			kg.BaseDomain = first[2:]
		} else {
			kg.BaseDomain = first
		}
	}

	allowlist := make(map[string]bool)
	for _, ip := range cfg.IPWhitelist {
		trimmed := strings.TrimSpace(ip)
		if parsed := net.ParseIP(trimmed); parsed != nil {
			allowlist[parsed.String()] = true
			kg.AddAllowedIP(parsed.String())
			kg.AddIP(parsed.String())
		}
	}
	for _, ip := range extractIPsFromTarget(target) {
		if len(allowlist) == 0 || allowlist[ip] {
			kg.AddAllowedIP(ip)
			kg.AddIP(ip)
		}
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			if ips, err := net.LookupIP(u.Hostname()); err == nil {
				for _, ip := range ips {
					kg.AddAllowedIP(ip.String())
				}
			}
		}
		kg.AddURL(target, target)
	} else if net.ParseIP(target) != nil {
		kg.AddAllowedIP(target)
		kg.AddIP(target)
	} else {
		if ips, err := net.LookupIP(target); err == nil {
			for _, ip := range ips {
				kg.AddAllowedIP(ip.String())
			}
		}
		kg.AddURL("http://"+target, "http://"+target)
	}
	for _, cred := range cfg.Credentials {
		if strings.TrimSpace(cred.Username) == "" {
			continue
		}
		kg.AddCredential(target, strings.TrimSpace(cred.Username), cred.Password)
	}
	kg.SetContextValue("ip_whitelist", cfg.IPWhitelist)
	kg.SetContextValue("rules_of_engagement", cfg.RulesOfEngagement)

	processedTargets := make(map[string]bool)
	globalIters := 0

	for {
		if reachedIterationLimit(globalIters, cfg.MaxIters) {
			log.Warnf("Global run loop reached MaxIters (%d). Stopping target scheduling.", cfg.MaxIters)
			break
		}

		var pendingTargets []string
		kg.RLock()
		for val := range kg.Targets {
			if !processedTargets[val] {
				pendingTargets = append(pendingTargets, val)
			}
		}
		kg.RUnlock()

		if len(pendingTargets) == 0 {
			break
		}

		for _, tVal := range pendingTargets {
			if reachedIterationLimit(globalIters, cfg.MaxIters) {
				log.Warnf("Global run loop reached MaxIters (%d). Skipping remaining pending targets.", cfg.MaxIters)
				break
			}
			processedTargets[tVal] = true
			log.Infof("Starting agent loop for target: %s", tVal)
			if err := runTargetAgent(ctx, tVal, target, cfg, kg, executor, model, allowlist, &globalIters); err != nil {
				log.Errorf("Target agent for %s failed: %v", tVal, err)
			}
		}
	}

	if !reachedIterationLimit(globalIters, cfg.MaxIters) {
		if preVulns, preErr := matrix.GetVulnerabilities(); preErr == nil {
			toolStageByName := make(map[string]matrix.Phase)
			var activeTools []fantasy.Tool
			for _, t := range executor.Tools() {
				toolStageByName[t.Name] = matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
				activeTools = append(activeTools, fantasy.FunctionTool{
					Name:        t.Name,
					Description: t.Description,
					InputSchema: t.InputSchema,
				})
			}

			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        "query_knowledge_graph",
				Description: "Query the knowledge graph for specific gathered intelligence.",
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{"query_type": map[string]any{"type": "string", "enum": []string{"ips", "urls", "ports", "credentials", "vulnerabilities", "tokens", "all"}}}, "required": []string{"query_type"}},
			})
			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        "log_vulnerability",
				Description: "Log or update a confirmed vulnerability finding for a target, including exploitability status. This marks the finding as processed.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"vuln_id": map[string]any{"type": "string"},
						"target":  map[string]any{"type": "string"},
						"finding": map[string]any{
							"type":        "string",
							"description": "A detailed description of the finding, including how it works, a descriptive summary, and step-by-step instructions to recreate the finding for further testing.",
						},
						"test_code":   map[string]any{"type": "string"},
						"exploitable": map[string]any{"type": "string", "enum": []string{"yes", "no"}},
					},
					"required": []string{"vuln_id", "target", "finding", "test_code", "exploitable"},
				},
			})

			for _, v := range preVulns {
				if strings.EqualFold(strings.TrimSpace(v.Processed), "no") {
					log.Infof("Processing remaining unprocessed vulnerability: target=%s vuln_id=%s finding=%q", v.TargetDomain, v.VulnID, v.Finding)
					_ = runVulnerabilityHelperSubAgent(ctx, model, v.TargetDomain, v.Finding, v.VulnID, activeTools, kg, executor, target, allowlist, toolStageByName)
					_ = matrix.MarkVulnerabilityProcessed(v.VulnID)
				}
			}
		}
	} else {
		log.Warnf("Skipping post-loop vulnerability helper processing because MaxIters (%d) was reached.", cfg.MaxIters)
	}


	var vulnsListStr string
	vulns, err := matrix.GetVulnerabilities()
	if err != nil {
		log.Warnf("Failed to query vulnerabilities: %v", err)
		vulnsListStr = "Error retrieving vulnerabilities from database."
	} else if len(vulns) > 0 {
		var sb strings.Builder
		sb.WriteString("Vulnerabilities detected during this engagement:\n\n")
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("- Target Domain: %s\n  Finding: %s\n  Date/Time: %s\n\n", v.TargetDomain, v.Finding, v.DateTime.Format(time.RFC3339)))
		}
		vulnsListStr = sb.String()
	} else {
		vulnsListStr = "No vulnerabilities were detected during the assessment."
	}

	reportStr := ""
	if model != nil {
		log.Infof("Generating final executive report via LLM...")
		reportPrompt := fmt.Sprintf("You are an expert security consultant. The red team engagement has concluded. Review the following summary of vulnerabilities detected. Write a comprehensive final executive summary and technical report. Your report should be formatted in markdown. Do NOT include any reproduction steps, commands, or code in the final report; focus on summarizing the scope, targets, and findings.\n\n%s", vulnsListStr)
		resp, err := model.Generate(ctx, fantasy.Call{
			Prompt: []fantasy.Message{
				{Role: "system", Content: []fantasy.MessagePart{fantasy.TextPart{Text: "You write final executive security reports."}}},
				fantasy.NewUserMessage(reportPrompt),
			},
		})
		if err == nil && len(resp.Content) > 0 {
			for _, c := range resp.Content {
				if tc, ok := c.(fantasy.TextContent); ok {
					reportStr += tc.Text
				}
			}
		} else if err != nil {
			log.Errorf("Failed to generate final report via LLM: %v", err)
		}
	}

	if reportStr == "" {
		reportStr = "# Final Report\n\n**Engagement Completed (Failed to generate narrative report).**\n\n"
	}

	if rawGraph, err := kg.ToJSON(""); err == nil {
		reportStr += "\n\n## Knowledge Graph Dump\n\n```json\n" + string(rawGraph) + "\n```\n"
	}

	reportPath := "fire_starter_report.md"
	var finalReport string
	if err := os.WriteFile(reportPath, []byte(reportStr), 0644); err != nil {
		log.Errorf("Failed to save report: %v", err)
		finalReport = fmt.Sprintf("Error saving report to %s: %v", reportPath, err)
	} else {
		log.Infof("Saved report to: %s", reportPath)
		finalReport = fmt.Sprintf("Report successfully saved to: %s", reportPath)
	}

	return finalReport, nil
}

func runTargetAgent(ctx context.Context, currentTarget string, initialTarget string, cfg Config, kg *matrix.KnowledgeGraph, executor *matrix.RealExecutor, model fantasy.LanguageModel, allowlist map[string]bool, globalIters *int) error {
	systemPrompt := `You are an autonomous red team agent assigned to a SPECIFIC target. Your current available tools are automatically populated based on the phase of the target.
Review the 'Current Intelligence Summary' in the system messages to see the global state, but your actions should focus on your assigned target.

Do not make assumptions. Turn theories into testable hypotheses, then validate them by calling available tools and using tool output as evidence for your next step. If evidence is missing or stale, call another tool instead of guessing. DO NOT write your own custom tools or scripts; you must use the provided tools for testing.

When you have exhausted all applicable tools for your target's current phase, you MUST call the 'advance_target_phase' tool for your target to unlock the next set of tools. If you find vulnerabilities, you MUST continue your investigation to probe deeper and attempt lateral movement. You may only call the 'target_completed' tool if you have exhausted all actionable tools for your assigned target, OR if you have found no vulnerabilities and your target has completed its reconnaissance phase.

When a vulnerability is confirmed, you MUST call 'log_vulnerability' with vuln_id, target, finding, test_code, and exploitable. Make sure the 'finding' parameter contains a detailed description of how the vulnerability works and step-by-step instructions to recreate it. Every confirmed vulnerability must be marked processed via this tool before moving from exploitation to post-exploitation. Use 'query_knowledge_graph' with query_type='vulnerabilities' to inspect the database-backed status list and get the vuln_id. If a vuln_id is missing, generate an md5 hash of (target + finding) to use as the vuln_id. For credential leaks (for example exposed .env), exploitable='yes' is only valid after you attempt credential-based authentication and verify it succeeds.

In vulnerability-analysis and exploitation phases, create and run one helper sub-agent per vulnerability per target to iterate and refine proof-of-concept testing against that target before deciding exploitability.

CRITICAL: Do not execute the same tool against the same target more than once. The framework will block duplicate payloads.
CRITICAL: Security testing is oriented around lateral movement within the network. Continue probing deeply.

Rules of Engagement (must be enforced in every decision):
%s

IP whitelist policy:
- Allowed IPs: %s
- If allowed IPs are "none", you may discover and probe any IP.
- If allowed IPs are specified, you MUST only choose tools and payloads that target those allowed IPs.`

	rules := strings.TrimSpace(cfg.RulesOfEngagement)
	if rules == "" {
		rules = "Follow standard legal and safe engagement boundaries."
	}
	formattedSystemPrompt := fmt.Sprintf(systemPrompt, rules, allowlistedIPsSummary(allowlist))
	if cfg.EfficiencyMode {
		formattedSystemPrompt = strings.Replace(formattedSystemPrompt, 
			"You may only call the 'target_completed' tool if you have exhausted all actionable tools for your assigned target, OR if you have found no vulnerabilities and your target has completed its reconnaissance phase.",
			"*** EFFICIENCY MODE ENABLED ***\nYou are authorized to triage targets aggressively. You MUST evaluate if the target is worth investigating purely based on its name/IP BEFORE gathering evidence. If it appears to be a low-value asset (e.g. static CDN, out of scope, uninteresting), call 'target_completed' immediately to skip it. You do NOT need evidence to skip a target.", 1)
	}

	userMsg := fmt.Sprintf("Begin engagement on target: %s", currentTarget)
	if cfg.EfficiencyMode {
		userMsg += "\nEvaluate this target for triage like an expert penetration tester. Think critically about what this target likely is based on its name and URL structure. Is it a static CDN? A purely informational marketing site? A standard API gateway? If your professional intuition tells you this is a low-value or low-likelihood target, you MUST call 'target_completed' immediately to skip it. Be ruthless with your time management."
	}

	history := []fantasy.Message{
		{
			Role:    "system",
			Content: []fantasy.MessagePart{fantasy.TextPart{Text: formattedSystemPrompt}},
		},
		fantasy.NewUserMessage(userMsg),
	}

	toolStageByName := make(map[string]matrix.Phase)
	for _, t := range executor.Tools() {
		stage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
		toolStageByName[t.Name] = stage
	}
	executedPayloads := make(map[string]bool)
	spawnedHelpers := make(map[string]bool)
	httpRequestState := &httpRequestGateState{}
	kg.RLock()
	if existingTarget := kg.Targets[currentTarget]; existingTarget != nil {
		httpRequestState.hasExecuted = contains(existingTarget.ExecutedTools, "decision_http_request")
		httpRequestState.lastTargetFingerprint = httpRequestTargetFingerprint(existingTarget)
		httpRequestState.lastAuthFingerprint = httpRequestAuthFingerprint(existingTarget)
	}
	kg.RUnlock()

	for {
		if *globalIters >= cfg.MaxIters {
			break
		}
		snapshot := kg.Snapshot()
		log.Infof("RED_TEAM_LOOP target=%s iteration=%d/%d %s", currentTarget, *globalIters+1, cfg.MaxIters, summarizeSnapshot(snapshot))
		*globalIters++

		scored := make([]scoredTool, 0)
		kg.RLock()
		targetObj := kg.Targets[currentTarget]
		if targetObj != nil {
			for _, t := range executor.Tools() {
				toolStage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
				if toolStage == targetObj.CurrentPhase || toolStage == matrix.PhaseReconnaissance || t.Name == "decision_http_request" {
					st := scoreTool(t, targetObj, snapshot, httpRequestState)
					if st.Score >= 0 {
						scored = append(scored, st)
					}
				}
			}
		}
		kg.RUnlock()

		uniqueScored := make(map[string]scoredTool)
		for _, st := range scored {
			if existing, ok := uniqueScored[st.Definition.Name]; ok {
				if st.Score > existing.Score {
					uniqueScored[st.Definition.Name] = st
				}
			} else {
				uniqueScored[st.Definition.Name] = st
			}
		}

		scoredList := make([]scoredTool, 0, len(uniqueScored))
		for _, st := range uniqueScored {
			scoredList = append(scoredList, st)
		}

		rand.Shuffle(len(scoredList), func(i, j int) {
			scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
		})

		sort.SliceStable(scoredList, func(i, j int) bool {
			return scoredList[i].Score > scoredList[j].Score
		})

		var activeTools []fantasy.Tool

		for rank, candidate := range scoredList {
			if rank >= 15 {
				break
			}
			if cfg.Verbose {
				log.Infof("TOOL_OPTION rank=%d tool=%s phase=%s score=%d reasons=%s", rank+1, candidate.Definition.Name, matrix.MapTechniqueToStage(candidate.Definition.Technique), candidate.Score, strings.Join(candidate.Reasons, "; "))
			}
			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        candidate.Definition.Name,
				Description: candidate.Definition.Description,
				InputSchema: candidate.Definition.InputSchema,
			})
		}

		var summaryBuilder strings.Builder
		summaryBuilder.WriteString("Current Intelligence Summary (Context for Tools):\n")
		normalizedCurrent := normalizeTarget(currentTarget)
		for _, t := range kg.Targets {
			normalizedT := normalizeTarget(t.Value)
			if normalizedT == normalizedCurrent {
				summaryBuilder.WriteString(fmt.Sprintf("- Target: %s (Phase: %s) [CURRENT TARGET]\n", t.Value, t.CurrentPhase))
				if len(t.OpenPorts) > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("  - Open Ports: %v\n", t.OpenPorts))
				}
				if len(t.Vulnerabilities) > 0 {
					summaryBuilder.WriteString("  - Vulnerabilities:\n")
					for _, vuln := range t.Vulnerabilities {
						summaryBuilder.WriteString(fmt.Sprintf("    * %s\n", vuln))
					}
				}
				if len(t.Tokens) > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("  - Session Tokens: %d harvested\n", len(t.Tokens)))
				}
				if len(t.Credentials) > 0 {
					summaryBuilder.WriteString("  - Credentials:\n")
					for _, cred := range t.Credentials {
						summaryBuilder.WriteString(fmt.Sprintf("    * Username: %s\n", cred.Username))
					}
				}
			} else {
				summaryBuilder.WriteString(fmt.Sprintf("- Target: %s (Phase: %s)\n", t.Value, t.CurrentPhase))
				if len(t.OpenPorts) > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("  - Open Ports: %v\n", t.OpenPorts))
				}
				if len(t.Vulnerabilities) > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("  - Vulns: %d found\n", len(t.Vulnerabilities)))
				}
			}
		}

		// Filter out any previous system summary messages to prevent history context accumulation
		cleanedHistory := make([]fantasy.Message, 0, len(history))
		for _, msg := range history {
			isOldSummary := false
			if msg.Role == "system" && len(msg.Content) > 0 {
				if tp, ok := msg.Content[0].(fantasy.TextPart); ok {
					if strings.HasPrefix(tp.Text, "Current Intelligence Summary") {
						isOldSummary = true
					}
				}
			}
			if !isOldSummary {
				cleanedHistory = append(cleanedHistory, msg)
			}
		}
		history = cleanedHistory

		history = append(history, fantasy.Message{
			Role:    "system",
			Content: []fantasy.MessagePart{fantasy.TextPart{Text: summaryBuilder.String()}},
		})

		canCompleteNow, submitReason := canCompleteTarget(snapshot, currentTarget, cfg.EfficiencyMode)
		log.Debugf("Phase controls: can_complete=%t reason=%s", canCompleteNow, submitReason)
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        "query_knowledge_graph",
			Description: "Query the knowledge graph for specific gathered intelligence.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query_type": map[string]any{
						"type": "string",
						"enum": []string{"ips", "urls", "ports", "credentials", "vulnerabilities", "tokens", "all"},
					},
				},
				"required": []string{"query_type"},
			},
		})
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        "advance_target_phase",
			Description: "Advance a specific target to the next red team phase after you have exhausted all applicable tools for its current phase.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type": "string",
					},
				},
				"required": []string{"target"},
			},
		})
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        "log_vulnerability",
			Description: "Log or update a confirmed vulnerability finding for a target, including exploitability status. This marks the finding as processed.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vuln_id": map[string]any{"type": "string"},
					"target":  map[string]any{"type": "string"},
					"finding": map[string]any{
						"type":        "string",
						"description": "A detailed description of the finding, including how it works, a descriptive summary, and step-by-step instructions to recreate the finding for further testing.",
					},
					"test_code":   map[string]any{"type": "string"},
					"exploitable": map[string]any{"type": "string", "enum": []string{"yes", "no"}},
				},
				"required": []string{"vuln_id", "target", "finding", "test_code", "exploitable"},
			},
		})
		
		if canCompleteNow || cfg.EfficiencyMode {
			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        "target_completed",
				Description: "Indicate to the orchestrator that you have completed all possible actions for your assigned target.",
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{"summary": map[string]any{"type": "string"}}, "required": []string{"summary"}},
			})
		}

		currentPhase := kg.GetTargetPhase(currentTarget)
		if currentPhase == matrix.PhaseVulnerabilityAnalysis || currentPhase == matrix.PhaseExploitation {
			helperQueue := collectHelperVulnQueue(currentTarget, kg)
			for _, v := range helperQueue {
				key := fmt.Sprintf("%s|%s", normalizeTarget(currentTarget), v.Finding)
				if spawnedHelpers[key] {
					continue
				}
				spawnedHelpers[key] = true

				helperOutput := runVulnerabilityHelperSubAgent(ctx, model, currentTarget, v.Finding, v.VulnID, activeTools, kg, executor, initialTarget, allowlist, toolStageByName)
				if strings.TrimSpace(helperOutput) != "" {
					history = append(history, fantasy.Message{
						Role:    "system",
						Content: []fantasy.MessagePart{fantasy.TextPart{Text: fmt.Sprintf("Helper sub-agent result for target '%s' finding '%s':\n%s", currentTarget, v.Finding, helperOutput)}},
					})
				}
			}
		}

		resp, err := model.Generate(ctx, fantasy.Call{
			Prompt: history,
			Tools:  activeTools,
		})
		if err != nil {
			log.Errorf("LLM error: %v. Retrying...", err)
			continue
		}

		assistantMsg := fantasy.Message{Role: "assistant"}
		for _, c := range resp.Content {
			switch v := c.(type) {
			case fantasy.TextContent:
				if strings.TrimSpace(v.Text) != "" {
					textToLog := v.Text
					if len(textToLog) > 500 {
						textToLog = textToLog[:500] + "... [Message truncated for display]"
					}
					log.Infof("LLM_CHAT_MESSAGE text=%q", textToLog)
				}
				assistantMsg.Content = append(assistantMsg.Content, fantasy.TextPart{Text: v.Text})
			case fantasy.ToolCallContent:
				assistantMsg.Content = append(assistantMsg.Content, fantasy.ToolCallPart{
					ToolCallID: v.ToolCallID,
					ToolName:   v.ToolName,
					Input:      v.Input,
				})
			}
		}
		history = append(history, assistantMsg)

		toolCalls := resp.Content.ToolCalls()
		if len(toolCalls) == 0 {
			history = append(history, fantasy.NewUserMessage("You did not call any tools. Do not assume outcomes—test your theory by calling an appropriate tool, or call the 'target_completed' tool if you are finished with this target."))
			continue
		}

		var toolResultParts []fantasy.MessagePart

		var submitTc *fantasy.ToolCallContent
		var otherTcs []fantasy.ToolCallContent

		for _, tc := range toolCalls {
			if tc.ToolName == "target_completed" {
				tcCopy := tc
				submitTc = &tcCopy
			} else {
				otherTcs = append(otherTcs, tc)
			}
		}

		for _, tc := range otherTcs {
			selectedPhase := matrix.PhaseReconnaissance
			if stage, ok := toolStageByName[tc.ToolName]; ok {
				selectedPhase = stage
			}
			log.Infof("TOOL_SELECTED tool=%s phase=%s", tc.ToolName, selectedPhase)

			if tc.ToolName == "advance_target_phase" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err == nil {
					if tStr, ok := args["target"].(string); ok && tStr != "" {
						normalizedTarget := normalizeTarget(tStr)
						currentPhase := kg.GetTargetPhase(normalizedTarget)
						if currentPhase == matrix.PhaseExploitation {
							vulns, err := matrix.GetVulnerabilities()
							if err != nil {
								toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
									ToolCallID: tc.ToolCallID,
									Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: failed to query vulnerabilities before phase transition: %v", err)},
								})
								continue
							}
							hasUnprocessed := false
							for _, v := range vulns {
								if normalizeTarget(v.TargetDomain) == normalizedTarget && strings.EqualFold(v.Processed, "no") {
									hasUnprocessed = true
									break
								}
							}
							if hasUnprocessed {
								toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
									ToolCallID: tc.ToolCallID,
									Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: cannot advance to post-exploitation while unprocessed vulnerabilities remain for this target. Call log_vulnerability for each finding first."},
								})
								continue
							}
						}
						newPhase := kg.AdvanceTargetPhase(normalizeTarget(tStr))
						toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
							ToolCallID: tc.ToolCallID,
							Output:     fantasy.ToolResultOutputContentText{Text: "Target advanced to next phase successfully."},
						})
						log.Infof("TARGET_PHASE_ADVANCED target=%s new_phase=%s", tStr, newPhase)
					} else {
						toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
							ToolCallID: tc.ToolCallID,
							Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Missing or empty target string."},
						})
					}
				} else {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Invalid JSON input."},
					})
				}
				continue
			}

			if tc.ToolName == "log_vulnerability" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: Invalid JSON input."},
					})
					continue
				}
				vulnID, _ := args["vuln_id"].(string)
				targetStr, _ := args["target"].(string)
				finding, _ := args["finding"].(string)
				testCode, _ := args["test_code"].(string)
				exploitable, _ := args["exploitable"].(string)

				// Enforce consistent vuln_id naming convention
				vulnID = matrix.GenerateVulnID(targetStr, finding)
				if validationErr := validateVulnerabilityLogInput(vulnID, targetStr, finding, testCode, exploitable); validationErr != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: %v", validationErr)},
					})
					continue
				}
				if err := matrix.LogVulnerability(vulnID, normalizeTarget(targetStr), finding, testCode, exploitable, "yes"); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: failed to log vulnerability: %v", err)},
					})
					continue
				}
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "Vulnerability logged and marked processed."},
				})
				continue
			}

			if tc.ToolName == "query_knowledge_graph" {
				var qArgs map[string]any
				_ = json.Unmarshal([]byte(tc.Input), &qArgs)
				qType, _ := qArgs["query_type"].(string)

				var resBytes []byte
				switch qType {
				case "ips":
					var ips []string
					for _, t := range kg.Targets {
						if t.Type == "ip" {
							ips = append(ips, t.Value)
						}
					}
					resBytes, _ = json.Marshal(ips)
				case "urls":
					var urls []string
					for _, t := range kg.Targets {
						if t.Type == "url" {
							urls = append(urls, t.Value)
						}
					}
					resBytes, _ = json.Marshal(urls)
				case "ports":
					ports := make(map[string][]int)
					for _, t := range kg.Targets {
						if len(t.OpenPorts) > 0 {
							ports[t.Value] = t.OpenPorts
						}
					}
					resBytes, _ = json.Marshal(ports)
				case "credentials":
					resBytes, _ = json.Marshal(kg.GetCredentials())
				case "vulnerabilities":
					vulns, err := matrix.GetVulnerabilities()
					if err != nil {
						resBytes, _ = json.Marshal(map[string]string{"error": fmt.Sprintf("failed to query vulnerabilities: %v", err)})
					} else {
						resBytes, _ = json.Marshal(vulns)
					}
				case "tokens":
					resBytes, _ = json.Marshal(kg.GetTokens())
				default:
					rawBytes, _ := kg.ToJSON(currentTarget)
					var data map[string]any
					if err := json.Unmarshal(rawBytes, &data); err == nil {
						// Strip test cases from targets to reduce prompt bloat
						if targets, ok := data["targets"].(map[string]any); ok {
							for _, tgt := range targets {
								if tgtMap, ok := tgt.(map[string]any); ok {
									delete(tgtMap, "test_cases")
								}
							}
						}
						resBytes, _ = json.Marshal(data)
					} else {
						resBytes = rawBytes
					}
				}

				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: string(resBytes)},
				})
				continue
			}


			var args map[string]any
			if tc.Input != "" {
				if err := json.Unmarshal([]byte(tc.Input), &args); err != nil {
					res := fmt.Sprintf("TOOL_ERROR: Failed to parse tool input JSON: %v", err)
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: res},
					})
					continue
				}
			}

			payload := make(map[string]any)
			if nested, ok := args["payload"].(map[string]any); ok {
				for k, v := range nested {
					payload[k] = v
				}
			}
			for k, v := range args {
				if k != "payload" {
					payload[k] = v
				}
			}

			if len(allowlist) > 0 && !isPayloadAllowedByIPWhitelist(payload, allowlist) {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output: fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: blocked by IP whitelist policy. Allowed IPs: " + allowlistedIPsSummary(allowlist)},
				})
				continue
			}

			payloadBytes, _ := json.Marshal(payload)
			payloadHash := fmt.Sprintf("%s|%s", tc.ToolName, string(payloadBytes))
			if executedPayloads[payloadHash] {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: You have already successfully executed this tool with this exact payload. Please choose a different target, a different tool, different parameters, or advance the phase."},
				})
				// log.Infof("TOOL_EXECUTION_BLOCKED reason=duplicate_payload tool=%s payload=%s", tc.ToolName, string(payloadBytes))
				continue
			}

			targetUsed := initialTarget
			if tStr, ok := payload["target"].(string); ok && strings.TrimSpace(tStr) != "" {
				targetUsed = strings.TrimSpace(tStr)
			} else if uStr, ok := payload["url"].(string); ok && strings.TrimSpace(uStr) != "" {
				targetUsed = strings.TrimSpace(uStr)
			} else if ipStr, ok := payload["ip"].(string); ok && strings.TrimSpace(ipStr) != "" {
				targetUsed = strings.TrimSpace(ipStr)
			}

			sessionID, hasSession := args["session_id"].(string)
			
			var sessionsToTest []string
			if hasSession && sessionID != "" {
				sessionsToTest = []string{sessionID}
			} else {
				sessionsToTest = []string{"unauthenticated", "default"}
			}

			var allSummaries []string
			var res string

			for _, sess := range sessionsToTest {
				// Clone payload so we don't bleed state between loop iterations
				iterPayload := make(map[string]any)
				for k, v := range payload {
					iterPayload[k] = v
				}
				
				if sess != "unauthenticated" {
					cookiesStr := kg.GetCookiesForRequest(sess, targetUsed)
					if cookiesStr != "" {
						iterPayload["cookies"] = cookiesStr
					}
					if _, hasUsername := iterPayload["username"]; !hasUsername {
						credentials := kg.GetCredentials() // Still using global credentials array for backward compatibility
						if len(credentials) > 0 {
							iterPayload["username"] = credentials[0].Username
							iterPayload["password"] = credentials[0].Password
						}
					}
				} else {
					iterPayload["cookies"] = ""
				}

				resultData, execErr := executor.ExecuteByToolName(tc.ToolName, iterPayload, func(s string) {
					log.Debug(s)
				})

				if execErr != nil {
					errStr := fmt.Sprintf("TOOL_ERROR (Session: %s): %v", sess, execErr)
					allSummaries = append(allSummaries, errStr)
					log.Debugf("TOOL_RESULT tool=%s session=%s status=error result=%s", tc.ToolName, sess, errStr)
				} else {
					executedPayloads[payloadHash] = true
					
					if t, ok := iterPayload["target"].(string); ok && strings.TrimSpace(t) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(t), tc.ToolName)
					}
					if u, ok := iterPayload["url"].(string); ok && strings.TrimSpace(u) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(u), tc.ToolName)
					}
					if ip, ok := iterPayload["ip"].(string); ok && strings.TrimSpace(ip) != "" {
						kg.MarkToolExecuted(strings.TrimSpace(ip), tc.ToolName)
					}

					beforeGraph := kg.Snapshot()
					summary, _, extractErr := kg.ExtractIntelligence(ctx, model, tc.ToolName, targetUsed, iterPayload, resultData)
					if extractErr != nil {
						log.Warnf("Intelligence extraction failed: %v", extractErr)
						summary = fmt.Sprintf("Tool executed successfully but intelligence extraction failed: %v", extractErr)
					}

					if err := matrix.LogExecution(initialTarget, resultData); err != nil {
						log.Warnf("Failed to log execution to SQLite: %v", err)
					}

					afterGraph := kg.Snapshot()
					if tc.ToolName == "decision_http_request" {
						kg.Lock()
						if targetObj := kg.Targets[currentTarget]; targetObj != nil {
							if targetObj.HTTPRequestGate == nil {
								targetObj.HTTPRequestGate = make(map[string]bool)
							}
							targetFingerprint := httpRequestTargetFingerprint(targetObj)
							authFingerprint := httpRequestAuthFingerprint(targetObj)
							if httpRequestState.hasExecuted && authFingerprint != httpRequestState.lastAuthFingerprint && targetFingerprint == httpRequestState.lastTargetFingerprint {
								targetObj.HTTPRequestGate[authReopenGateKey(targetFingerprint, authFingerprint)] = true
							}
							updateHTTPRequestGateState(httpRequestState, targetObj)
						}
						kg.Unlock()
					}
					log.Infof("KNOWLEDGE_GRAPH_UPDATE tool=%s session=%s delta=%s snapshot=%s", tc.ToolName, sess, snapshotDelta(beforeGraph, afterGraph), summarizeSnapshot(afterGraph))
					_, _ = canCompleteTarget(afterGraph, currentTarget, cfg.EfficiencyMode)
					log.Infof("TOOL_EXECUTION_SUMMARY tool=%s target=%s session=%s summary=%q", tc.ToolName, targetUsed, sess, summary)
					allSummaries = append(allSummaries, fmt.Sprintf("[Session: %s] %s", sess, summary))
				}
			}
			
			res = fmt.Sprintf("=== TOOL EXECUTION SUMMARY ===\n%s", strings.Join(allSummaries, "\n\n"))

			toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
				ToolCallID: tc.ToolCallID,
				Output:     fantasy.ToolResultOutputContentText{Text: res},
			})
		}

		if submitTc != nil {
			tc := *submitTc
			selectedPhase := matrix.PhaseReconnaissance
			if stage, ok := toolStageByName[tc.ToolName]; ok {
				selectedPhase = stage
			}
			log.Infof("TOOL_SELECTED tool=%s phase=%s", tc.ToolName, selectedPhase)

			ok, reason := canCompleteTarget(kg.Snapshot(), currentTarget, cfg.EfficiencyMode)
			if !ok {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: target_completed blocked: " + reason},
				})
			} else {
				kg.SetTargetPhase(currentTarget, matrix.PhaseReporting)
				log.Infof("Target %s completed successfully and moved to reporting phase.", currentTarget)
				saveTargetReport(ctx, currentTarget, cfg, kg, model)
				return nil
			}
		}

		if len(toolResultParts) > 0 {
			history = append(history, fantasy.Message{
				Role:    "tool",
				Content: toolResultParts,
			})
		}
	}

	log.Warnf("Target agent for %s reached MaxIters (%d) without completing.", currentTarget, cfg.MaxIters)
	kg.SetTargetPhase(currentTarget, matrix.PhaseReporting)
	saveTargetReport(ctx, currentTarget, cfg, kg, model)
	return nil
}

func saveTargetReport(ctx context.Context, target string, cfg Config, kg *matrix.KnowledgeGraph, model fantasy.LanguageModel) {
	log.Infof("Assessment completed for target: %s. Transitioned to reporting phase.", target)
}
