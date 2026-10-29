package agent

import (
	"context"
	"fmt"
	"strings"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
)

// collectHelperVulnQueue assembles the queue of candidate findings for a
// target that still need helper validation: unresolved findings attached to
// the knowledge-graph target plus database-backed candidates for it.
func collectHelperVulnQueue(currentTarget string, kg *matrix.KnowledgeGraph) []matrix.VulnInfo {
	queue := make([]matrix.VulnInfo, 0)
	seen := make(map[string]bool)
	normalizedTarget := normalizeTarget(currentTarget)

	resolvedFindings := make(map[string]bool)
	if vulns, err := matrix.GetVulnerabilities(); err == nil {
		for _, v := range vulns {
			if normalizeTarget(v.TargetDomain) == normalizedTarget {
				if v.Status == matrix.VulnerabilityStatusConfirmed || v.Status == matrix.VulnerabilityStatusInformational || v.Status == matrix.VulnerabilityStatusDisproven {
					resolvedFindings[strings.TrimSpace(v.Finding)] = true
				}
			}
		}
	}

	if t, ok := kg.GetTarget(normalizedTarget); ok {
		for _, finding := range t.Vulnerabilities {
			trimmed := strings.TrimSpace(finding)
			if trimmed != "" && !seen[trimmed] && !resolvedFindings[trimmed] {
				seen[trimmed] = true

				// Generate a consistent vuln_id hash
				vid := matrix.GenerateVulnID(normalizedTarget, trimmed)

				queue = append(queue, matrix.VulnInfo{Finding: trimmed, VulnID: vid, Status: matrix.VulnerabilityStatusCandidate})
			}
		}
	}

	if vulns, err := matrix.GetVulnerabilities(); err == nil {
		for _, v := range vulns {
			if normalizeTarget(v.TargetDomain) != normalizedTarget {
				continue
			}
			if v.Status == matrix.VulnerabilityStatusCandidate {
				trimmed := strings.TrimSpace(v.Finding)
				if trimmed != "" && !seen[trimmed] && !resolvedFindings[trimmed] {
					seen[trimmed] = true
					queue = append(queue, v)
				}
			}
		}
	}

	return queue
}

// buildHelperHistory creates the opening history for a helper sub-agent run:
// a focused system message plus a user message carrying the finding to
// validate and the knowledge-graph snapshot for the target.
func buildHelperHistory(env *agentEnv, currentTarget string, finding string, origVulnID string) []fantasy.Message {
	var rawGraph []byte
	if rawBytes, err := env.kg.ToJSONWithoutTestCases(currentTarget); err == nil {
		rawGraph = rawBytes
	}
	prompt := fmt.Sprintf("You are a vulnerability helper sub-agent. Focus only on target '%s' and finding '%s' (vuln_id: %s). Use the available tools to validate exploitability and refine proof-of-concept evidence. DO NOT write your own custom tools or scripts; you must use the provided tools for testing. If this is a confirmed security vulnerability, call log_vulnerability with status='confirmed', severity='critical'|'high'|'medium'|'low'|'unknown', vuln_id, target, finding, exploitable yes/no and concise test_code. If this is a confirmed informational observation rather than a vulnerability, call log_vulnerability with status='informational' and severity='informational'. Make sure the 'finding' parameter contains a detailed description of how the issue works and step-by-step instructions to recreate it. For exposed credentials (e.g. .env leaks), do not set exploitable='yes' unless you successfully authenticate using the leaked credentials and include that evidence in test_code. If not enough evidence, do not log it as confirmed or informational.", currentTarget, finding, origVulnID)

	history := []fantasy.Message{
		{Role: "system", Content: []fantasy.MessagePart{fantasy.TextPart{Text: "You are a focused vulnerability helper sub-agent. DO NOT write your own custom tools or scripts; you must use the provided tools for testing."}}},
		fantasy.NewUserMessage(prompt + "\n\nKnowledge Graph Snapshot:\n" + string(rawGraph)),
	}
	return history
}

// appendTextParts joins collected assistant text into the helper transcript.
func appendTextParts(out *strings.Builder, textParts []string) {
	for _, t := range textParts {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString(t)
	}
}

// runHelperToolCalls dispatches every tool call of a helper turn and wraps the
// results in a single tool message for the transcript.
func runHelperToolCalls(ctx context.Context, env *agentEnv, toolCalls []fantasy.ToolCallContent, origVulnID string) fantasy.Message {
	var toolResultParts []fantasy.MessagePart
	for _, tc := range toolCalls {
		log.Infof("Helper tool call: %s", tc.ToolName)
		res, _ := dispatchToolCall(ctx, env, tc, origVulnID)
		toolResultParts = append(toolResultParts, fantasy.ToolResultPart{
			ToolCallID: tc.ToolCallID,
			Output:     fantasy.ToolResultOutputContentText{Text: res},
		})
	}
	return fantasy.Message{
		Role:    "tool",
		Content: toolResultParts,
	}
}

// runVulnerabilityHelperSubAgent validates a single candidate finding against
// a target. It runs a short LLM loop over the provided tools (sharing the
// unified dispatch), then marks the finding disproven if no resolved status
// was logged within the iteration budget.
func runVulnerabilityHelperSubAgent(ctx context.Context, env *agentEnv, currentTarget string, finding string, origVulnID string, activeTools []fantasy.Tool) string {
	prevTarget := env.currentTarget
	env.currentTarget = currentTarget
	defer func() { env.currentTarget = prevTarget }()

	env.vulnLogged = false

	history := buildHelperHistory(env, currentTarget, finding, origVulnID)

	var out strings.Builder

	for turn := 0; turn < 5; turn++ {
		if ctx.Err() != nil {
			break
		}
		if env.globalIters != nil && env.cfg.MaxIters > 0 && *env.globalIters >= env.cfg.MaxIters {
			log.Warnf("Helper sub-agent reached global MaxIters (%d). Stopping.", env.cfg.MaxIters)
			break
		}
		if env.globalIters != nil {
			*env.globalIters++
		}
		history = compactHistory(history, 6)
		resp, err := generateWithRetry(ctx, env.model, fantasy.Call{
			Prompt: history,
			Tools:  activeTools,
		}, 3)
		if err != nil {
			log.Errorf("Helper LLM error: %v", err)
			break
		}

		assistantMsg, textParts := buildAssistantMessage(resp, false)
		history = append(history, assistantMsg)

		toolCalls := resp.Content.ToolCalls()
		if len(toolCalls) == 0 {
			appendTextParts(&out, textParts)
			break
		}

		history = append(history, runHelperToolCalls(ctx, env, toolCalls, origVulnID))

		appendTextParts(&out, textParts)
	}

	if !env.vulnLogged {
		log.Infof("Helper exhausted iterations without confirmed or informational finding, marking disproven for vuln_id=%s", origVulnID)
		_ = matrix.MarkVulnerabilityDisproven(origVulnID)
	}

	return out.String()
}
