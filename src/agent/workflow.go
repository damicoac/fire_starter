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

func getApplicableTargets(t matrix.ToolDefinition, kg *matrix.KnowledgeGraph, baseTarget string) []string {
	bytes, err := kg.ToJSON()
	if err != nil {
		return []string{baseTarget}
	}
	var state struct {
		Targets map[string]struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"targets"`
	}
	json.Unmarshal(bytes, &state)

	hasURL := false
	hasIP := false
	if props, ok := t.InputSchema["properties"].(map[string]any); ok {
		if _, ok := props["url"]; ok {
			hasURL = true
		}
		if _, ok := props["endpoint"]; ok {
			hasURL = true
		}
		if _, ok := props["ip"]; ok {
			hasIP = true
		}
	}

	var targets []string
	if hasURL {
		for _, t := range state.Targets {
			if t.Type == "url" {
				targets = append(targets, normalizeTarget(t.Value))
			}
		}
	}
	if hasIP {
		for _, t := range state.Targets {
			if t.Type == "ip" {
				targets = append(targets, normalizeTarget(t.Value))
			}
		}
	}
	if len(targets) == 0 {
		targets = append(targets, normalizeTarget(baseTarget))
	}
	return targets
}

func normalizeTarget(t string) string {
	return matrix.NormalizeURL(t)
}

func hasPort(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}

func scoreTool(def matrix.ToolDefinition, target *matrix.Target, snapshot matrix.KnowledgeSnapshot) scoredTool {
	stage := matrix.Phase(matrix.MapTechniqueToStage(def.Technique))
	score := 0
	reasons := make([]string, 0, 4)

	for _, exec := range target.ExecutedTools {
		if exec == def.Name {
			return scoredTool{Definition: def, Score: -100, Reasons: []string{"already executed on this target"}}
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

func canSubmit(snapshot matrix.KnowledgeSnapshot) (bool, string) {
	if snapshot.VulnerabilityCount > 0 {
		return true, "vulnerabilities found"
	}
	allReporting := true
	for _, phase := range snapshot.TargetPhases {
		if phase != matrix.PhaseReporting {
			allReporting = false
			break
		}
	}
	if len(snapshot.TargetPhases) > 0 && allReporting {
		return true, "all targets exhausted"
	}
	return false, "no vulnerabilities and targets not exhausted"
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

func recommendedNextAction(canSubmitNow bool, submitReason string) string {
	if canSubmitNow {
		return "submit (" + submitReason + ")"
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

func getBaseDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return hostname
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
	kg.OnUpdate = onKGUpdate

	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		kg.BaseDomain = getBaseDomain(u.Hostname())
	} else if !strings.HasPrefix(target, "http") {
		u, err := url.Parse("https://" + target)
		if err == nil && u.Hostname() != "" {
			kg.BaseDomain = getBaseDomain(u.Hostname())
		}
	}

	allowlist := make(map[string]bool)
	for _, ip := range cfg.IPWhitelist {
		trimmed := strings.TrimSpace(ip)
		if parsed := net.ParseIP(trimmed); parsed != nil {
			allowlist[parsed.String()] = true
			kg.AddIP(parsed.String())
		}
	}
	for _, ip := range extractIPsFromTarget(target) {
		if len(allowlist) == 0 || allowlist[ip] {
			kg.AddIP(ip)
		}
	}
	for _, cred := range cfg.Credentials {
		if strings.TrimSpace(cred.Username) == "" {
			continue
		}
		kg.AddCredential(target, strings.TrimSpace(cred.Username), cred.Password)
	}
	kg.SetContextValue("ip_whitelist", cfg.IPWhitelist)
	kg.SetContextValue("rules_of_engagement", cfg.RulesOfEngagement)

	systemPrompt := `You are an autonomous red team agent. Your current available tools are automatically populated based on the phase of the targets you have discovered. 
Review the 'Current Intelligence Summary' in the system messages to see what targets exist, what state they are in, and what ports/vulns they have.

Do not make assumptions. Turn theories into testable hypotheses, then validate them by calling available tools and using tool output as evidence for your next step. If evidence is missing or stale, call another tool instead of guessing.

When you have exhausted all applicable tools for a target's current phase, you MUST call the 'advance_target_phase' tool for that target to unlock the next set of tools. When you have reached your goals, found critical vulnerabilities, or run out of actionable tools across all targets, you MUST call the 'submit' tool with your final report. Your report should thoroughly summarize the findings from the engagement and provide the security engineer with everything they need to do follow on work. The final report will automatically include the exact reproduction steps for the vulnerabilities based on your execution history, so you do not need to retrieve them.

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

		history := []fantasy.Message{
		{
			Role:    "system",
			Content: []fantasy.MessagePart{fantasy.TextPart{Text: formattedSystemPrompt}},
		},
		fantasy.NewUserMessage(fmt.Sprintf("Begin engagement on target: %s", target)),
	}

	toolStageByName := make(map[string]matrix.Phase)
	for _, t := range executor.Tools() {
		stage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
		toolStageByName[t.Name] = stage
	}
	executedPayloads := make(map[string]bool)

	for iter := 0; iter < cfg.MaxIters; iter++ {
		snapshot := kg.Snapshot()
		log.Infof("RED_TEAM_LOOP iteration=%d/%d %s", iter+1, cfg.MaxIters, summarizeSnapshot(snapshot))

		scored := make([]scoredTool, 0)
		for _, targetObj := range kg.Targets {
			for _, t := range executor.Tools() {
				toolStage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
				
				if toolStage == targetObj.CurrentPhase || toolStage == matrix.PhaseReconnaissance {
					st := scoreTool(t, targetObj, snapshot)
					if st.Score >= 0 {
						scored = append(scored, st)
					}
				}
			}
		}

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
		for _, t := range kg.Targets {
			summaryBuilder.WriteString(fmt.Sprintf("- Target: %s (Phase: %s)\n", t.Value, t.CurrentPhase))
			if len(t.OpenPorts) > 0 {
				summaryBuilder.WriteString(fmt.Sprintf("  - Open Ports: %v\n", t.OpenPorts))
			}
			if len(t.Vulnerabilities) > 0 {
				summaryBuilder.WriteString(fmt.Sprintf("  - Vulns: %d found\n", len(t.Vulnerabilities)))
			}
		}

		history = append(history, fantasy.Message{
			Role:    "system",
			Content: []fantasy.MessagePart{fantasy.TextPart{Text: summaryBuilder.String()}},
		})

		canSubmitNow, submitReason := canSubmit(snapshot)
		log.Debugf("Phase controls: can_submit=%t reason=%s", canSubmitNow, submitReason)
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
		
		if canSubmitNow {
			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        "submit",
				Description: "Submit the final engagement report.",
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{"report": map[string]any{"type": "string"}}, "required": []string{"report"}},
			})
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
			history = append(history, fantasy.NewUserMessage("You did not call any tools. Do not assume outcomes—test your theory by calling an appropriate tool, or call the 'submit' tool if you are finished."))
			continue
		}

		var toolResultParts []fantasy.MessagePart

		for _, tc := range toolCalls {
			selectedPhase := matrix.PhaseReconnaissance
			if stage, ok := toolStageByName[tc.ToolName]; ok {
				selectedPhase = stage
			}
			log.Infof("TOOL_SELECTED tool=%s phase=%s", tc.ToolName, selectedPhase)

			if tc.ToolName == "submit" {
				ok, reason := canSubmit(kg.Snapshot())
				if !ok {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: submit blocked: " + reason},
					})
					continue
				}

				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err != nil {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: fmt.Sprintf("TOOL_ERROR: invalid JSON: %v", err)},
					})
					continue
				}

				reportStr, ok := args["report"].(string)
				if !ok {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: The 'report' argument is missing or not a string. Please call submit again with the report string."},
					})
					continue
				}

				reportPath := "fire_starter_report.md"

				if kgJSON, err := kg.ToJSON(); err == nil {
					reportStr += "\n\n## Appendix: Knowledge Graph Dump\n\n```json\n" + string(kgJSON) + "\n```\n"
				}

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

			if tc.ToolName == "advance_target_phase" {
				var args map[string]any
				if err := json.Unmarshal([]byte(tc.Input), &args); err == nil {
					if tStr, ok := args["target"].(string); ok && tStr != "" {
						kg.AdvanceTargetPhase(normalizeTarget(tStr))
						toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
							ToolCallID: tc.ToolCallID,
							Output:     fantasy.ToolResultOutputContentText{Text: "Target advanced to next phase successfully."},
						})
						log.Infof("TARGET_PHASE_ADVANCED target=%s", tStr)
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
					var vulns []string
					for _, t := range kg.Targets {
						vulns = append(vulns, t.Vulnerabilities...)
					}
					resBytes, _ = json.Marshal(vulns)
				case "tokens":
					resBytes, _ = json.Marshal(kg.GetTokens())
				default:
					rawBytes, _ := kg.ToJSON()
					var data map[string]any
					if err := json.Unmarshal(rawBytes, &data); err == nil {
						delete(data, "test_cases")
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

			tokens := kg.GetTokens()
			if len(tokens) > 0 {
				payload["cookies"] = strings.Join(tokens, "; ")
			}
			if _, hasUsername := payload["username"]; !hasUsername {
				credentials := kg.GetCredentials()
				if len(credentials) > 0 {
					payload["username"] = credentials[0].Username
					payload["password"] = credentials[0].Password
				}
			}

			payloadBytes, _ := json.Marshal(payload)
			payloadHash := fmt.Sprintf("%s|%s", tc.ToolName, string(payloadBytes))
			if executedPayloads[payloadHash] {
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: You have already successfully executed this tool with this exact payload. Please choose a different target, a different tool, different parameters, or advance the phase."},
				})
				log.Infof("TOOL_EXECUTION_BLOCKED reason=duplicate_payload tool=%s payload=%s", tc.ToolName, string(payloadBytes))
				continue
			}

			resultData, execErr := executor.ExecuteByToolName(tc.ToolName, payload, func(s string) {
				log.Debug(s)
			})

			var res string
			if execErr != nil {
				res = fmt.Sprintf("TOOL_ERROR: %v", execErr)
				log.Warnf("Tool error in %s: %v", tc.ToolName, execErr)
				log.Debugf("TOOL_RESULT tool=%s status=error result=%s", tc.ToolName, res)
			} else {
				executedPayloads[payloadHash] = true

				targetUsed := target
				if tStr, ok := payload["target"].(string); ok && strings.TrimSpace(tStr) != "" {
					targetUsed = strings.TrimSpace(tStr)
				} else if uStr, ok := payload["url"].(string); ok && strings.TrimSpace(uStr) != "" {
					targetUsed = strings.TrimSpace(uStr)
				} else if ipStr, ok := payload["ip"].(string); ok && strings.TrimSpace(ipStr) != "" {
					targetUsed = strings.TrimSpace(ipStr)
				}


				if t, ok := payload["target"].(string); ok && strings.TrimSpace(t) != "" {
					kg.MarkToolExecuted(strings.TrimSpace(t), tc.ToolName)
				}
				if u, ok := payload["url"].(string); ok && strings.TrimSpace(u) != "" {
					kg.MarkToolExecuted(strings.TrimSpace(u), tc.ToolName)
				}
				if ip, ok := payload["ip"].(string); ok && strings.TrimSpace(ip) != "" {
					kg.MarkToolExecuted(strings.TrimSpace(ip), tc.ToolName)
				}

				beforeGraph := kg.Snapshot()
				summary, extractErr := kg.ExtractIntelligence(ctx, model, tc.ToolName, targetUsed, payload, resultData)
				if extractErr != nil {
					log.Warnf("Intelligence extraction failed: %v", extractErr)
					summary = fmt.Sprintf("Tool executed successfully but intelligence extraction failed: %v", extractErr)
				}
				afterGraph := kg.Snapshot()
				log.Infof("KNOWLEDGE_GRAPH_UPDATE tool=%s delta=%s snapshot=%s", tc.ToolName, snapshotDelta(beforeGraph, afterGraph), summarizeSnapshot(afterGraph))
				canSubmitAfter, submitReasonAfter := canSubmit(afterGraph)
				log.Infof("NEXT_DECISION tool=%s recommendation=%s", tc.ToolName, recommendedNextAction(canSubmitAfter, submitReasonAfter))
				log.Infof("TOOL_EXECUTION_SUMMARY tool=%s summary=%q", tc.ToolName, summary)
				res = fmt.Sprintf("=== TOOL EXECUTION SUMMARY ===\n%s", summary)
				log.Debugf("TOOL_RESULT tool=%s status=success result=%s", tc.ToolName, resultData)
			}

			toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
				ToolCallID: tc.ToolCallID,
				Output:     fantasy.ToolResultOutputContentText{Text: res},
			})
		}

		if len(toolResultParts) > 0 {
			history = append(history, fantasy.Message{
				Role:    "tool",
				Content: toolResultParts,
			})
		}


	}


	reportStr := "# Final Report\n\n**WARNING: The application reached the maximum number of iterations without completing the red team process.**\n\n"
	reportPath := "fire_starter_report.md"

	if kgJSON, err := kg.ToJSON(); err == nil {
		reportStr += "## Appendix: Knowledge Graph Dump\n\n```json\n" + string(kgJSON) + "\n```\n"
	}

	var finalReport string
	if err := os.WriteFile(reportPath, []byte(reportStr), 0644); err != nil {
		log.Errorf("Failed to save report: %v", err)
		finalReport = fmt.Sprintf("Error saving report to %s: %v", reportPath, err)
	} else {
		log.Infof("Saved report to: %s", reportPath)
		finalReport = fmt.Sprintf("Report successfully saved to: %s (Note: Max iterations reached before completion)", reportPath)
	}

	return finalReport, nil
}
