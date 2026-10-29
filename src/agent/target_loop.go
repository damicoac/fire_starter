package agent

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
)

// compactHistory trims a transcript to the most recent messages, keeping the
// system header and condensing older tool results to bounded text.
func compactHistory(history []fantasy.Message, maxRecentMessages int) []fantasy.Message {
	if len(history) <= 6 {
		return history
	}

	var header []fantasy.Message
	var intermediate []fantasy.Message

	if len(history) > 0 && history[0].Role == "system" {
		header = append(header, history[0])
		if len(history) > 1 && history[1].Role == "user" {
			header = append(header, history[1])
			intermediate = history[2:]
		} else {
			intermediate = history[1:]
		}
	} else {
		intermediate = history
	}

	if len(intermediate) <= maxRecentMessages {
		result := make([]fantasy.Message, 0, len(header)+len(intermediate))
		result = append(result, header...)
		result = append(result, intermediate...)
		return result
	}

	cutoff := len(intermediate) - maxRecentMessages
	older := intermediate[:cutoff]
	recent := intermediate[cutoff:]

	const maxOlderMessages = 16
	if len(older) > maxOlderMessages {
		older = older[len(older)-maxOlderMessages:]
	}

	condensedOlder := make([]fantasy.Message, 0, len(older))
	for _, msg := range older {
		if msg.Role == "tool" {
			var condensedParts []fantasy.MessagePart
			for _, part := range msg.Content {
				if trp, ok := part.(fantasy.ToolResultPart); ok {
					condensedOutput := trp.Output
					if tc, isText := trp.Output.(fantasy.ToolResultOutputContentText); isText {
						text := tc.Text
						if len(text) > 150 {
							text = text[:150] + "... [Historical execution condensed]"
						}
						condensedOutput = fantasy.ToolResultOutputContentText{Text: text}
					}
					condensedParts = append(condensedParts, fantasy.ToolResultPart{
						ToolCallID: trp.ToolCallID,
						Output:     condensedOutput,
					})
				} else {
					condensedParts = append(condensedParts, part)
				}
			}
			condensedOlder = append(condensedOlder, fantasy.Message{
				Role:    "tool",
				Content: condensedParts,
			})
		} else {
			condensedOlder = append(condensedOlder, msg)
		}
	}

	result := make([]fantasy.Message, 0, len(header)+len(condensedOlder)+len(recent))
	result = append(result, header...)
	result = append(result, condensedOlder...)
	result = append(result, recent...)
	return result
}

// buildAssistantMessage converts an LLM response into a transcript message and
// returns the collected text parts. With logChat set (target loop) text is
// echoed to the log truncated and empty text parts are preserved; helper mode
// keeps only non-empty text parts.
func buildAssistantMessage(resp *fantasy.Response, logChat bool) (fantasy.Message, []string) {
	assistantMsg := fantasy.Message{Role: "assistant"}
	var textParts []string
	for _, c := range resp.Content {
		switch v := c.(type) {
		case fantasy.TextContent:
			nonEmpty := strings.TrimSpace(v.Text) != ""
			if nonEmpty {
				textParts = append(textParts, v.Text)
				if logChat {
					textToLog := v.Text
					if len(textToLog) > 500 {
						textToLog = textToLog[:500] + "... [Message truncated for display]"
					}
					log.Infof("LLM_CHAT_MESSAGE text=%q", textToLog)
				}
			}
			if logChat || nonEmpty {
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
	return assistantMsg, textParts
}

// assemblePrompt renders the per-target system prompt: rules of engagement,
// IP whitelist policy, and the efficiency-mode override.
func assemblePrompt(cfg Config, allowlist map[string]bool) string {
	systemTemplate := `You are an autonomous red team agent assigned to a SPECIFIC target. Your current available tools are automatically populated based on the phase of the target.
Review the 'Current Intelligence Summary' in the system messages to see the global state, but your actions should focus on your assigned target.

Do not make assumptions. Turn theories into testable hypotheses, then validate them by calling available tools and using tool output as evidence for your next step. If evidence is missing or stale, call another tool instead of guessing. DO NOT write your own custom tools or scripts; you must use the provided tools for testing.

When you have exhausted all applicable tools for your target's current phase, you MUST call the 'advance_target_phase' tool for your target to unlock the next set of tools. If you find vulnerabilities, you MUST continue your investigation to probe deeper and attempt lateral movement. You may only call the 'target_completed' tool if you have exhausted all actionable tools for your assigned target, OR if you have found no vulnerabilities and your target has completed its reconnaissance phase.

When a vulnerability is confirmed, you MUST call 'log_vulnerability' with vuln_id, target, finding, test_code, exploitable, status, and severity. Make sure the 'finding' parameter contains a detailed description of how the vulnerability works and step-by-step instructions to recreate it. Use 'query_knowledge_graph' with query_type='vulnerabilities' to inspect the database-backed status list and get the vuln_id. If a vuln_id is missing, generate an md5 hash of (target + finding) to use as the vuln_id. For credential leaks (for example exposed .env), exploitable='yes' is only valid after you attempt credential-based authentication and verify it succeeds.

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
	systemPrompt := fmt.Sprintf(systemTemplate, rules, allowlistedIPsSummary(allowlist))
	if cfg.EfficiencyMode {
		systemPrompt = strings.Replace(systemPrompt,
			"You may only call the 'target_completed' tool if you have exhausted all actionable tools for your assigned target, OR if you have found no vulnerabilities and your target has completed its reconnaissance phase.",
			"*** EFFICIENCY MODE ENABLED ***\nYou are authorized to triage targets aggressively. You MUST evaluate if the target is worth investigating purely based on its name/IP BEFORE gathering evidence. If it appears to be a low-value asset (e.g. static CDN, out of scope, uninteresting), call 'target_completed' immediately to skip it. You do NOT need evidence to skip a target.", 1)
	}

	return systemPrompt
}

// buildTargetOpeningHistory creates the opening transcript for a target loop.
func buildTargetOpeningHistory(env *agentEnv, currentTarget string) []fantasy.Message {
	systemPrompt := assemblePrompt(env.cfg, env.allowlist)
	userMsg := fmt.Sprintf("Begin engagement on target: %s", currentTarget) + efficiencySuffix(env.cfg)
	history := []fantasy.Message{
		{
			Role:    "system",
			Content: []fantasy.MessagePart{fantasy.TextPart{Text: systemPrompt}},
		},
		fantasy.NewUserMessage(userMsg),
	}
	return history
}

// efficiencySuffix returns the extra triage guidance appended to the opening
// user message in efficiency mode.
func efficiencySuffix(cfg Config) string {
	if !cfg.EfficiencyMode {
		return ""
	}
	return "\nEvaluate this target for triage like an expert penetration tester. Think critically about what this target likely is based on its name and URL structure. Is it a static CDN? A purely informational marketing site? A standard API gateway? If your professional intuition tells you this is a low-value or low-likelihood target, you MUST call 'target_completed' immediately to skip it. Be ruthless with your time management."
}

// initHTTPRequestGateState seeds the decision_http_request gate bookkeeping
// from the target's persisted execution history.
func initHTTPRequestGateState(kg *matrix.KnowledgeGraph, currentTarget string) *httpRequestGateState {
	state := &httpRequestGateState{}
	if existingTarget, ok := kg.GetTarget(currentTarget); ok {
		state.hasExecuted = contains(existingTarget.ExecutedTools, "decision_http_request")
		state.lastTargetFingerprint = httpRequestTargetFingerprint(existingTarget)
		state.lastAuthFingerprint = httpRequestAuthFingerprint(existingTarget)
	}
	return state
}

// rankTools filters the executor's technique tools to those applicable to the
// target's current phase, scores them, dedupes by name keeping the best score,
// then randomizes ties and sorts descending.
func rankTools(env *agentEnv, targetObj *matrix.Target, snapshot matrix.KnowledgeSnapshot, httpRequestState *httpRequestGateState) []scoredTool {
	scored := make([]scoredTool, 0)
	if targetObj == nil {
		return scored
	}
	for _, t := range env.executor.Tools() {
		toolStage := matrix.Phase(t.Phase)
		if toolStage == targetObj.CurrentPhase || toolStage == matrix.PhaseReconnaissance || t.Name == "decision_http_request" {
			st := scoreTool(t, targetObj, snapshot, httpRequestState)
			if st.Score >= 0 {
				scored = append(scored, st)
			}
		}
	}
	return dedupeAndRankTools(scored)
}

// dedupeAndRankTools collapses same-name candidates to their highest score,
// shuffles to randomize equal-score ordering, then sorts descending.
func dedupeAndRankTools(scored []scoredTool) []scoredTool {
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
	return scoredList
}

// selectTopTools exposes only the top-ranked candidates to the LLM.
func selectTopTools(env *agentEnv, scoredList []scoredTool) []fantasy.Tool {
	var activeTools []fantasy.Tool

	for rank, candidate := range scoredList {
		if rank >= 15 {
			break
		}
		if env.cfg.Verbose {
			log.Infof("TOOL_OPTION rank=%d tool=%s phase=%s score=%d reasons=%s", rank+1, candidate.Definition.Name, candidate.Definition.Phase, candidate.Score, strings.Join(candidate.Reasons, "; "))
		}
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        candidate.Definition.Name,
			Description: candidate.Definition.Description,
			InputSchema: candidate.Definition.InputSchema,
		})
	}
	return activeTools
}

func queryKnowledgeGraphTool() fantasy.FunctionTool {
	return fantasy.FunctionTool{
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
	}
}

func advanceTargetPhaseTool() fantasy.FunctionTool {
	return fantasy.FunctionTool{
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
	}
}

func logVulnerabilityTool() fantasy.FunctionTool {
	return fantasy.FunctionTool{
		Name:        "log_vulnerability",
		Description: "Log or update a confirmed vulnerability or informational finding for a target. Candidate and disproven findings must not be logged with this tool.",
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
				"status":      map[string]any{"type": "string", "enum": []string{"confirmed", "informational"}},
				"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational", "unknown"}},
			},
			"required": []string{"vuln_id", "target", "finding", "test_code", "exploitable", "status", "severity"},
		},
	}
}

func targetCompletedTool() fantasy.FunctionTool {
	return fantasy.FunctionTool{
		Name:        "target_completed",
		Description: "Indicate to the orchestrator that you have completed all possible actions for your assigned target.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"summary": map[string]any{"type": "string"}}, "required": []string{"summary"}},
	}
}

// appendControlTools adds the fixed control-plane tools every target loop
// exposes, plus the completion tool when the target may be completed.
func appendControlTools(env *agentEnv, activeTools []fantasy.Tool, canCompleteNow bool) []fantasy.Tool {
	activeTools = append(activeTools, queryKnowledgeGraphTool())
	activeTools = append(activeTools, advanceTargetPhaseTool())
	activeTools = append(activeTools, logVulnerabilityTool())
	if canCompleteNow || env.cfg.EfficiencyMode {
		activeTools = append(activeTools, targetCompletedTool())
	}
	return activeTools
}

// currentTargetObject fetches the knowledge-graph target record for the
// target currently being processed, or nil when it is unknown.
func currentTargetObject(env *agentEnv, currentTarget string) *matrix.Target {
	targetObj, ok := env.kg.GetTarget(currentTarget)
	if !ok {
		return nil
	}
	return targetObj
}

// buildIntelligenceSummary renders the Current Intelligence Summary block the
// target loop injects as a system message each iteration.
func buildIntelligenceSummary(env *agentEnv, currentTarget string) string {
	var summaryBuilder strings.Builder
	summaryBuilder.WriteString("Current Intelligence Summary (Context for Tools):\n")
	normalizedCurrent := normalizeTarget(currentTarget)
	for _, t := range env.kg.GetTargetsSnapshot() {
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
	if env.kg != nil && env.kg.Memory != nil {
		observations := env.kg.Memory.Query(currentTarget, 3)
		if len(observations) > 0 {
			summaryBuilder.WriteString("Recent Observations:\n")
			for _, obs := range observations {
				summaryBuilder.WriteString(fmt.Sprintf("- %s\n", obs.Entry.Content))
			}
		}
	}
	return summaryBuilder.String()
}

// appendIntelligenceSummary drops previous intelligence-summary system
// messages from the transcript (to prevent context accumulation) and appends
// a freshly rendered one.
func appendIntelligenceSummary(env *agentEnv, history []fantasy.Message, currentTarget string) []fantasy.Message {
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

	return append(cleanedHistory, fantasy.Message{
		Role:    "system",
		Content: []fantasy.MessagePart{fantasy.TextPart{Text: buildIntelligenceSummary(env, currentTarget)}},
	})
}

// runHelperQueue spawns one helper sub-agent per unresolved candidate finding
// of the current target while it is in the vulnerability-analysis or
// exploitation phase, feeding each result back into the transcript.
func runHelperQueue(ctx context.Context, env *agentEnv, history []fantasy.Message, activeTools []fantasy.Tool, spawnedHelpers map[string]bool) []fantasy.Message {
	currentPhase := env.kg.GetTargetPhase(env.currentTarget)
	if currentPhase != matrix.PhaseVulnerabilityAnalysis && currentPhase != matrix.PhaseExploitation {
		return history
	}
	for _, v := range collectHelperVulnQueue(env.currentTarget, env.kg) {
		key := fmt.Sprintf("%s|%s", normalizeTarget(env.currentTarget), v.Finding)
		if spawnedHelpers[key] {
			continue
		}
		spawnedHelpers[key] = true

		helperOutput := runVulnerabilityHelperSubAgent(ctx, env, env.currentTarget, v.Finding, v.VulnID, activeTools)
		if strings.TrimSpace(helperOutput) != "" {
			history = append(history, fantasy.Message{
				Role:    "system",
				Content: []fantasy.MessagePart{fantasy.TextPart{Text: fmt.Sprintf("Helper sub-agent result for target '%s' finding '%s':\n%s", env.currentTarget, v.Finding, helperOutput)}},
			})
		}
	}
	return history
}

// splitSubmitToolCall separates a target_completed call from the remaining
// tool calls of a response.
func splitSubmitToolCall(toolCalls []fantasy.ToolCallContent) (*fantasy.ToolCallContent, []fantasy.ToolCallContent) {
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
	return submitTc, otherTcs
}

// handleSubmitToolCall enforces the completion controls for target_completed:
// the target moves to the reporting phase only when canCompleteTarget allows
// it. It reports whether the target loop should stop.
func handleSubmitToolCall(ctx context.Context, env *agentEnv, currentTarget string, tc fantasy.ToolCallContent) (bool, string) {
	selectedPhase := matrix.PhaseReconnaissance
	if stage, ok := env.toolStageByName[tc.ToolName]; ok {
		selectedPhase = stage
	}
	log.Infof("TOOL_SELECTED tool=%s phase=%s", tc.ToolName, selectedPhase)

	ok, reason := canCompleteTarget(env.kg.Snapshot(), currentTarget, env.cfg.EfficiencyMode)
	if !ok {
		return false, reason
	}
	env.kg.SetTargetPhase(currentTarget, matrix.PhaseReporting)
	log.Infof("Target %s completed successfully and moved to reporting phase.", currentTarget)
	saveTargetReport(ctx, currentTarget, env.cfg, env.kg, env.model)
	return true, ""
}

// runTargetAgent drives the LLM loop for one target: it ranks and exposes the
// phase-appropriate tools, dispatches every tool call through the shared
// dispatchToolCall, spawns helper sub-agents for candidate findings, and
// finishes the target when it completes or the iteration budget runs out.
func runTargetAgent(ctx context.Context, env *agentEnv, currentTarget string) error {
	env.currentTarget = currentTarget
	env.httpRequestState = initHTTPRequestGateState(env.kg, currentTarget)
	env.payloadHashes = make(map[string]bool)

	history := buildTargetOpeningHistory(env, currentTarget)
	spawnedHelpers := make(map[string]bool)
	consecutiveLLMErrors := 0

	for {
		if *env.globalIters >= env.cfg.MaxIters {
			break
		}
		snapshot := env.kg.Snapshot()
		log.Infof("RED_TEAM_LOOP target=%s iteration=%d/%d %s", currentTarget, *env.globalIters+1, env.cfg.MaxIters, summarizeSnapshot(snapshot))
		*env.globalIters++

		targetObj := currentTargetObject(env, currentTarget)
		techniqueTools := selectTopTools(env, rankTools(env, targetObj, snapshot, env.httpRequestState))

		history = appendIntelligenceSummary(env, history, currentTarget)

		canCompleteNow, submitReason := canCompleteTarget(snapshot, currentTarget, env.cfg.EfficiencyMode)
		log.Debugf("Phase controls: can_complete=%t reason=%s", canCompleteNow, submitReason)
		activeTools := appendControlTools(env, techniqueTools, canCompleteNow)

		history = runHelperQueue(ctx, env, history, activeTools, spawnedHelpers)

		history = compactHistory(history, 8)
		resp, err := generateWithRetry(ctx, env.model, fantasy.Call{
			Prompt: history,
			Tools:  activeTools,
		}, 3)
		if err != nil {
			consecutiveLLMErrors++
			log.Errorf("LLM error after retries (consecutive %d): %v. Pausing before retry...", consecutiveLLMErrors, err)
			if consecutiveLLMErrors >= 5 {
				return fmt.Errorf("exceeded maximum consecutive LLM errors (5): %w", err)
			}
			if env.globalIters != nil {
				*env.globalIters--
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
			}
			continue
		}
		consecutiveLLMErrors = 0

		assistantMsg, _ := buildAssistantMessage(resp, true)
		history = append(history, assistantMsg)

		toolCalls := resp.Content.ToolCalls()
		if len(toolCalls) == 0 {
			history = append(history, fantasy.NewUserMessage("You did not call any tools. Do not assume outcomes—test your theory by calling an appropriate tool, or call the 'target_completed' tool if you are finished with this target."))
			continue
		}

		submitTc, otherTcs := splitSubmitToolCall(toolCalls)

		var toolResultParts []fantasy.MessagePart
		for _, tc := range otherTcs {
			res, _ := dispatchToolCall(ctx, env, tc, "")
			toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
				ToolCallID: tc.ToolCallID,
				Output:     fantasy.ToolResultOutputContentText{Text: res},
			})
		}

		if submitTc != nil {
			completed, blockReason := handleSubmitToolCall(ctx, env, currentTarget, *submitTc)
			if completed {
				return nil
			}
			toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
				ToolCallID: submitTc.ToolCallID,
				Output:     fantasy.ToolResultOutputContentText{Text: "TOOL_ERROR: target_completed blocked: " + blockReason},
			})
		}

		if len(toolResultParts) > 0 {
			history = append(history, fantasy.Message{
				Role:    "tool",
				Content: toolResultParts,
			})
		}
	}

	log.Warnf("Target agent for %s reached MaxIters (%d) without completing.", currentTarget, env.cfg.MaxIters)
	env.kg.SetTargetPhase(currentTarget, matrix.PhaseReporting)
	saveTargetReport(ctx, currentTarget, env.cfg, env.kg, env.model)
	return nil
}
