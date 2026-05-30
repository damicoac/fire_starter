package agent

import (
	"context"
	"encoding/json"
	"fmt"
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
		DiscoveredIPs []struct{ Value string } `json:"discovered_ips"`
		DiscoveredURLs []struct{ Value string } `json:"discovered_urls"`
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
		for _, u := range state.DiscoveredURLs {
			targets = append(targets, normalizeTarget(u.Value))
		}
	}
	if hasIP {
		for _, ip := range state.DiscoveredIPs {
			targets = append(targets, normalizeTarget(ip.Value))
		}
	}
	if len(targets) == 0 {
		targets = append(targets, normalizeTarget(baseTarget))
	}
	return targets
}

func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimRight(t, "/")
	return t
}

func isToolExhausted(t matrix.ToolDefinition, kg *matrix.KnowledgeGraph, baseTarget string, executedTargets map[string]bool) bool {
	if executedTargets == nil {
		return false
	}
	applicable := getApplicableTargets(t, kg, baseTarget)
	for _, target := range applicable {
		if !executedTargets[target] {
			return false
		}
	}
	return true
}

func scoreTool(def matrix.ToolDefinition, currentPhase matrix.Phase, snapshot matrix.KnowledgeSnapshot, exhausted bool) scoredTool {
	stage := matrix.Phase(matrix.MapTechniqueToStage(def.Technique))
	score := 0
	reasons := make([]string, 0, 4)

	switch {
	case stage == currentPhase:
		score += 10
		reasons = append(reasons, "in current phase")
	case stage == matrix.PhaseReconnaissance:
		score += 3
		reasons = append(reasons, "always-recon exception")
	}

	switch stage {
	case matrix.PhaseReconnaissance:
		if snapshot.DiscoveredIPCount == 0 {
			score += 4
			reasons = append(reasons, "no discovered IPs")
		}
		if snapshot.DiscoveredURLCount == 0 {
			score += 4
			reasons = append(reasons, "no discovered URLs")
		}
	case matrix.PhaseScanning:
		if snapshot.OpenPortCount == 0 {
			score += 5
			reasons = append(reasons, "no open ports yet")
		}
	case matrix.PhaseVulnerabilityAnalysis:
		if snapshot.VulnerabilityCount == 0 {
			score += 4
			reasons = append(reasons, "no vulnerabilities confirmed")
		}
	case matrix.PhaseExploitation:
		if snapshot.VulnerabilityCount > 0 {
			score += 3
			reasons = append(reasons, "vulnerabilities available to exploit")
		}
	case matrix.PhasePostExploitation:
		if snapshot.HarvestedTokenCount > 0 {
			score += 3
			reasons = append(reasons, "tokens available for post-exploitation")
		}
	}

	if exhausted {
		score -= 5
		reasons = append(reasons, "exhausted against all targets")
	} else {
		score += 5
		reasons = append(reasons, "targets remaining to test")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "baseline")
	}

	return scoredTool{Definition: def, Score: score, Reasons: reasons}
}

func completedInPhase(completedByPhase map[matrix.Phase]map[string]map[string]bool, phase matrix.Phase, executor *matrix.RealExecutor, kg *matrix.KnowledgeGraph, baseTarget string) int {
	entries, ok := completedByPhase[phase]
	if !ok {
		return 0
	}
	return len(entries)
}

func canAdvancePhase(currentPhase matrix.Phase, completedByPhase map[matrix.Phase]map[string]map[string]bool, toolsByPhase map[matrix.Phase]int, executor *matrix.RealExecutor, kg *matrix.KnowledgeGraph, baseTarget string) (bool, string) {
	completed := completedInPhase(completedByPhase, currentPhase, executor, kg, baseTarget)

	switch currentPhase {
	case matrix.PhaseReconnaissance:
		snapshot := kg.Snapshot()
		if completed >= 2 || (completed >= 1 && (snapshot.DiscoveredIPCount > 0 || snapshot.DiscoveredURLCount > 0)) {
			return true, "reconnaissance evidence captured"
		}
		return false, "need at least one to two recon actions plus discovered targets"
	case matrix.PhaseScanning:
		snapshot := kg.Snapshot()
		if completed >= 1 && (snapshot.OpenPortCount > 0 || snapshot.DiscoveredURLCount > 0) {
			return true, "scanning produced usable surface"
		}
		return false, "need at least one scanning action and discovered services/URLs"
	case matrix.PhaseVulnerabilityAnalysis:
		snapshot := kg.Snapshot()
		if completed >= 1 && (snapshot.VulnerabilityCount > 0 || snapshot.HarvestedTokenCount > 0) {
			return true, "analysis produced exploitable findings"
		}
		return false, "need at least one analysis action and findings/tokens"
	case matrix.PhaseExploitation:
		if completed >= 1 {
			return true, "exploitation actions executed"
		}
		return false, "need at least one exploitation action"
	case matrix.PhasePostExploitation:
		snapshot := kg.Snapshot()
		if completed >= 1 || snapshot.HarvestedTokenCount > 0 {
			return true, "post-exploitation coverage complete"
		}
		return false, "need at least one post-exploitation action"
	default:
		return false, "already at terminal phase"
	}
}

func canSubmit(currentPhase matrix.Phase, completedByPhase map[matrix.Phase]map[string]map[string]bool, snapshot matrix.KnowledgeSnapshot, toolsByPhase map[matrix.Phase]int, executor *matrix.RealExecutor, kg *matrix.KnowledgeGraph, baseTarget string) (bool, string) {
	if currentPhase == matrix.PhaseReporting {
		return true, "in reporting phase"
	}

	requiredPhases := []matrix.Phase{
		matrix.PhaseReconnaissance,
		matrix.PhaseScanning,
		matrix.PhaseVulnerabilityAnalysis,
		matrix.PhaseExploitation,
	}
	missing := make([]string, 0, len(requiredPhases))
	for _, phase := range requiredPhases {
		if completedInPhase(completedByPhase, phase, executor, kg, baseTarget) == 0 {
			missing = append(missing, string(phase))
		}
	}
	if len(missing) > 0 {
		return false, "missing phase coverage: " + strings.Join(missing, ", ")
	}
	if snapshot.VulnerabilityCount == 0 {
		return false, "no confirmed vulnerability signals"
	}
	return true, "explicit completion criteria met"
}

func summarizeSnapshot(snapshot matrix.KnowledgeSnapshot) string {
	return fmt.Sprintf("phase=%s ips=%d urls=%d open_ports=%d vulnerabilities=%d tokens=%d",
		snapshot.CurrentPhase,
		snapshot.DiscoveredIPCount,
		snapshot.DiscoveredURLCount,
		snapshot.OpenPortCount,
		snapshot.VulnerabilityCount,
		snapshot.HarvestedTokenCount,
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

func recommendedNextAction(currentPhase matrix.Phase, canAdvanceNow bool, advanceReason string, canSubmitNow bool, submitReason string) string {
	if canSubmitNow {
		return "submit (" + submitReason + ")"
	}
	if canAdvanceNow {
		return "advance_phase (" + advanceReason + ")"
	}
	return "continue_phase " + string(currentPhase) + " (" + advanceReason + ")"
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
				out[ip.String()] = true
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

func RunAgent(ctx context.Context, target string, cfg Config, onKGUpdate func(*matrix.KnowledgeGraph), onPrompt func(choices []string) int) (string, error) {
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
		kg.AddCredential(strings.TrimSpace(cred.Username), cred.Password)
	}
	kg.SetContextValue("ip_whitelist", cfg.IPWhitelist)
	kg.SetContextValue("rules_of_engagement", cfg.RulesOfEngagement)

	systemPrompt := `You are an intelligent security testing agent following a strict Red Team lifecycle: Reconnaissance -> Scanning -> Vulnerability Analysis -> Exploitation -> Post-Exploitation -> Reporting.

You currently only have access to tools for your current phase. When you have exhausted the interesting attack surface for your current phase, you MUST call the 'advance_phase' tool to unlock the next set of tools. State is persisted in the Knowledge Graph. Note that security testing is oriented around lateral movement within the network.

Do not make assumptions. Turn theories into testable hypotheses, then validate them by calling available tools and using tool output as evidence for your next step. If evidence is missing or stale, call another tool instead of guessing.

When you have reached your goals or finished all phases, you MUST call the 'submit' tool with your final report.

CRITICAL: Do not execute the same tool against the same target more than once. The Knowledge Graph tracks 'executed_tools' for each discovered target. Always check a target's executed tools before scanning to avoid infinite loops.

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
	toolsByPhase := make(map[matrix.Phase]int)
	for _, t := range executor.Tools() {
		stage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
		toolStageByName[t.Name] = stage
		toolsByPhase[stage]++
	}
	completedByPhase := make(map[matrix.Phase]map[string]map[string]bool)

	for iter := 0; iter < cfg.MaxIters; iter++ {
		currentPhase := kg.GetCurrentPhase()
		snapshot := kg.Snapshot()
		log.Infof("RED_TEAM_LOOP iteration=%d/%d %s", iter+1, cfg.MaxIters, summarizeSnapshot(snapshot))
		scored := make([]scoredTool, 0)
		for _, t := range executor.Tools() {
			toolStage := matrix.Phase(matrix.MapTechniqueToStage(t.Technique))
			if toolStage == currentPhase || toolStage == matrix.PhaseReconnaissance {
				var executedTargets map[string]bool
				if completedByPhase[toolStage] != nil {
					executedTargets = completedByPhase[toolStage][t.Name]
				}
				exhausted := isToolExhausted(t, kg, target, executedTargets)
				scored = append(scored, scoreTool(t, currentPhase, snapshot, exhausted))
				continue
			}
			log.Debugf("Tool rejected this phase: %s stage=%s current_phase=%s", t.Name, toolStage, currentPhase)
		}

		sort.SliceStable(scored, func(i, j int) bool {
			if scored[i].Score == scored[j].Score {
				return scored[i].Definition.Identifier < scored[j].Definition.Identifier
			}
			return scored[i].Score > scored[j].Score
		})

			var activeTools []fantasy.Tool
		var chosenCandidate *scoredTool

		if cfg.HumanLoop && len(scored) > 0 {
			var formattedChoices []string
			numChoices := len(scored)
			if numChoices > 3 {
				numChoices = 3
			}
			for i := 0; i < numChoices; i++ {
				c := scored[i]
				choiceStr := fmt.Sprintf("%s (Phase: %s) - Score: %d [Reasons: %s]",
					c.Definition.Name,
					matrix.MapTechniqueToStage(c.Definition.Technique),
					c.Score,
					strings.Join(c.Reasons, "; "),
				)
				formattedChoices = append(formattedChoices, choiceStr)
			}
			
			// Show prompt
			chosenIndex := onPrompt(formattedChoices)
			if chosenIndex >= 0 && chosenIndex < len(scored) {
				chosen := scored[chosenIndex]
				chosenCandidate = &chosen
				
				// Force model to use chosen tool
				history = append(history, fantasy.NewUserMessage(fmt.Sprintf(
					"The user has explicitly selected to execute the tool '%s'. You MUST call this tool next.", 
					chosen.Definition.Name,
				)))
			}
		}

		if chosenCandidate != nil {
			activeTools = append(activeTools, fantasy.FunctionTool{
				Name:        chosenCandidate.Definition.Name,
				Description: chosenCandidate.Definition.Description,
				InputSchema: chosenCandidate.Definition.InputSchema,
			})
		} else {
			for rank, candidate := range scored {
				if cfg.HumanLoop && (cfg.Verbose || rank < 3) {
					log.Infof("TOOL_OPTION rank=%d tool=%s phase=%s score=%d reasons=%s", rank+1, candidate.Definition.Name, matrix.MapTechniqueToStage(candidate.Definition.Technique), candidate.Score, strings.Join(candidate.Reasons, "; "))
				}
				activeTools = append(activeTools, fantasy.FunctionTool{
					Name:        candidate.Definition.Name,
					Description: candidate.Definition.Description,
					InputSchema: candidate.Definition.InputSchema,
				})
			}
		}

		canAdvanceNow, advanceReason := canAdvancePhase(currentPhase, completedByPhase, toolsByPhase, executor, kg, target)
		canSubmitNow, submitReason := canSubmit(currentPhase, completedByPhase, snapshot, toolsByPhase, executor, kg, target)
		log.Debugf("Phase controls: can_advance=%t reason=%s can_submit=%t reason=%s", canAdvanceNow, advanceReason, canSubmitNow, submitReason)
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        "query_knowledge_graph",
			Description: "Query the knowledge graph for specific gathered intelligence.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query_type": map[string]any{
						"type": "string",
						"enum": []string{"ips", "urls", "ports", "credentials", "vulnerabilities", "tokens", "test_cases", "all"},
					},
				},
				"required": []string{"query_type"},
			},
		})
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        "advance_phase",
			Description: "Advance to the next red team phase only after current phase completion criteria are satisfied.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
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
			return "", fmt.Errorf("LLM error: %w", err)
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
			selectedPhase := kg.GetCurrentPhase()
			if stage, ok := toolStageByName[tc.ToolName]; ok {
				selectedPhase = stage
			}
			log.Infof("TOOL_SELECTED tool=%s phase=%s", tc.ToolName, selectedPhase)

			if tc.ToolName == "submit" {
				ok, reason := canSubmit(kg.GetCurrentPhase(), completedByPhase, kg.Snapshot(), toolsByPhase, executor, kg, target)
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

				kg.SetCurrentPhase(matrix.PhaseReporting)
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

			if tc.ToolName == "query_knowledge_graph" {
				var qArgs map[string]any
				_ = json.Unmarshal([]byte(tc.Input), &qArgs)
				qType, _ := qArgs["query_type"].(string)

				var resBytes []byte
				switch qType {
				case "ips":
					resBytes, _ = json.Marshal(kg.DiscoveredIPs)
				case "urls":
					resBytes, _ = json.Marshal(kg.DiscoveredURLs)
				case "ports":
					resBytes, _ = json.Marshal(kg.OpenPorts)
				case "credentials":
					resBytes, _ = json.Marshal(kg.KnownCredentials)
				case "vulnerabilities":
					resBytes, _ = json.Marshal(kg.Vulnerabilities)
				case "tokens":
					resBytes, _ = json.Marshal(kg.HarvestedTokens)
				case "test_cases":
					resBytes, _ = json.Marshal(kg.TestCases)
				default:
					resBytes, _ = kg.ToJSON()
				}

				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: string(resBytes)},
				})
				continue
			}

			if tc.ToolName == "advance_phase" {
				priorPhase := kg.GetCurrentPhase()
				ok, reason := canAdvancePhase(priorPhase, completedByPhase, toolsByPhase, executor, kg, target)
				if !ok {
					toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
						ToolCallID: tc.ToolCallID,
						Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: advance blocked: " + reason},
					})
					continue
				}
				newPhase := kg.AdvancePhase()
				log.Infof("PHASE_TRANSITION from=%s to=%s reason=%s", priorPhase, newPhase, reason)
				res := fmt.Sprintf("Advanced to phase: %s", newPhase)
				toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
					ToolCallID: tc.ToolCallID,
					Output:     fantasy.ToolResultOutputContentText{Text: res},
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

			resultData, execErr := executor.ExecuteByToolName(tc.ToolName, payload, func(s string) {
				log.Debug(s)
			})

			var res string
			if execErr != nil {
				res = fmt.Sprintf("TOOL_ERROR: %v", execErr)
				log.Warnf("Tool error in %s: %v", tc.ToolName, execErr)
				log.Debugf("TOOL_RESULT tool=%s status=error result=%s", tc.ToolName, res)
			} else {
				if phase, ok := toolStageByName[tc.ToolName]; ok {
					if completedByPhase[phase] == nil {
						completedByPhase[phase] = make(map[string]map[string]bool)
					}
					if completedByPhase[phase][tc.ToolName] == nil {
						completedByPhase[phase][tc.ToolName] = make(map[string]bool)
					}
					
					targetUsed := target
					if tStr, ok := payload["target"].(string); ok && strings.TrimSpace(tStr) != "" {
						targetUsed = strings.TrimSpace(tStr)
					} else if uStr, ok := payload["url"].(string); ok && strings.TrimSpace(uStr) != "" {
						targetUsed = strings.TrimSpace(uStr)
					} else if ipStr, ok := payload["ip"].(string); ok && strings.TrimSpace(ipStr) != "" {
						targetUsed = strings.TrimSpace(ipStr)
					}
					completedByPhase[phase][tc.ToolName][normalizeTarget(targetUsed)] = true
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
				summary, extractErr := kg.ExtractIntelligence(ctx, model, tc.ToolName, target, payload, resultData)
				if extractErr != nil {
					log.Warnf("Intelligence extraction failed: %v", extractErr)
					summary = fmt.Sprintf("Tool executed successfully but intelligence extraction failed: %v", extractErr)
				}
				afterGraph := kg.Snapshot()
				log.Infof("KNOWLEDGE_GRAPH_UPDATE tool=%s delta=%s snapshot=%s", tc.ToolName, snapshotDelta(beforeGraph, afterGraph), summarizeSnapshot(afterGraph))
				canAdvanceAfter, advanceReasonAfter := canAdvancePhase(afterGraph.CurrentPhase, completedByPhase, toolsByPhase, executor, kg, target)
				canSubmitAfter, submitReasonAfter := canSubmit(afterGraph.CurrentPhase, completedByPhase, afterGraph, toolsByPhase, executor, kg, target)
				log.Infof("NEXT_DECISION tool=%s recommendation=%s", tc.ToolName, recommendedNextAction(afterGraph.CurrentPhase, canAdvanceAfter, advanceReasonAfter, canSubmitAfter, submitReasonAfter))
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
	return "", fmt.Errorf("max iterations reached without calling 'submit'")
}
