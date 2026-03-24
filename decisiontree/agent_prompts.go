package decisiontree

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PromptPlan defines the stage-specific guidance contract used to compose prompts.
type PromptPlan struct {
	Role               string
	Goals              []string
	DecisionChecks     []string
	OutputRequirements []string
}

// BuildStagePrompt builds an instructions block and user prompt payload for one stage transition.
func BuildStagePrompt(input ThirdPartyInput, result ToolResult) (string, string, error) {
	plan := promptPlanForStage(input.Stage)
	contextJSON, err := buildStageContextJSON(input, result)
	if err != nil {
		return "", "", err
	}

	instructions := strings.Join([]string{
		"You are a side-by-side security review copilot supporting a human analyst during a live penetration-testing workflow.",
		"Focus on practical, defensible security guidance mapped to the current stage of the decision tree.",
		"Prioritize actions that reduce false positives and preserve evidence quality.",
		"Never invent tool output. If context is missing, state assumptions clearly and provide a validation step.",
		fmt.Sprintf("Current role for this stage: %s", plan.Role),
	}, "\n")

	userPrompt := strings.Join([]string{
		"Generate stage guidance for the analyst and for the decision-tree handoff.",
		"",
		"Stage goals:",
		formatBullets(plan.Goals),
		"",
		"Decision checks:",
		formatBullets(plan.DecisionChecks),
		"",
		"Output requirements:",
		formatBullets(plan.OutputRequirements),
		"",
		"Execution context (JSON):",
		contextJSON,
	}, "\n")

	return instructions, userPrompt, nil
}

// promptPlanForStage selects a prompt plan tuned to the active module prefix.
func promptPlanForStage(stage string) PromptPlan {
	if strings.HasPrefix(stage, "api-testing.") {
		return PromptPlan{
			Role: "API security test strategist",
			Goals: []string{
				"Summarize attack intent and expected evidence for this API stage.",
				"Recommend precise next checks the human should run side-by-side with the agent.",
				"Call out likely bypass patterns and verification probes.",
			},
			DecisionChecks: []string{
				"Confirm the stage output supports the next stage transition.",
				"Flag missing artifacts needed for reproducible findings.",
				"Identify whether severity should be escalated based on observed indicators.",
			},
			OutputRequirements: []string{
				"Return a concise stage summary.",
				"Return a numbered checklist of immediate analyst actions.",
				"Return a decision note indicating whether branch assumptions remain valid.",
			},
		}
	}

	if strings.HasPrefix(stage, "application-mapping.") {
		return PromptPlan{
			Role: "Application attack-surface mapper",
			Goals: []string{
				"Translate mapping outputs into exploitable attack-surface hypotheses.",
				"Highlight trust boundaries, data flows, and privileged functionality.",
				"Prepare concrete pivots for active testing stages.",
			},
			DecisionChecks: []string{
				"Confirm discovered entry points are sufficient to proceed.",
				"Identify blind spots and enumerate what evidence is still missing.",
				"Mark high-value targets that should be prioritized in testing.",
			},
			OutputRequirements: []string{
				"Return prioritized attack-surface areas with rationale.",
				"Return a short list of follow-up probes by endpoint or workflow.",
				"Return confidence level for mapping completeness.",
			},
		}
	}

	if strings.HasPrefix(stage, "active-testing.") {
		return PromptPlan{
			Role: "Exploit validation and triage partner",
			Goals: []string{
				"Assess exploitability and business impact of current active tests.",
				"Distinguish confirmatory signals from noise.",
				"Recommend minimal safe retests to validate reproducibility.",
			},
			DecisionChecks: []string{
				"Confirm prerequisites for current exploit class are met.",
				"Identify contradictions requiring branch correction or rollback.",
				"Mark whether evidence quality is sufficient for reporting.",
			},
			OutputRequirements: []string{
				"Return likely impact statement tied to observed behavior.",
				"Return concrete retest commands or probes.",
				"Return reporting notes including caveats and confidence.",
			},
		}
	}

	return PromptPlan{
		Role: "Security workflow coordinator",
		Goals: []string{
			"Align current stage outputs with the broader testing objective.",
			"Identify the most useful next actions for the analyst.",
			"Keep branch decisions explicit and auditable.",
		},
		DecisionChecks: []string{
			"Validate that transition conditions are satisfied.",
			"Call out data-quality issues that can derail next stages.",
			"Recommend safeguards against false positives.",
		},
		OutputRequirements: []string{
			"Return stage summary, next actions, and branch decision notes.",
		},
	}
}

// buildStageContextJSON serializes stage execution context for deterministic prompt grounding.
func buildStageContextJSON(input ThirdPartyInput, result ToolResult) (string, error) {
	contextPayload := map[string]any{
		"stage":         input.Stage,
		"input_payload": input.Payload,
		"tool_name":     result.ToolName,
		"tool_calls":    result.Calls,
		"output":        result.Output,
	}
	encoded, err := json.MarshalIndent(contextPayload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal stage context: %w", err)
	}
	return string(encoded), nil
}

// formatBullets normalizes prompt sections into markdown bullet lists.
func formatBullets(items []string) string {
	if len(items) == 0 {
		return "- none"
	}

	lines := make([]string, len(items))
	for i := range items {
		lines[i] = fmt.Sprintf("- %s", items[i])
	}
	return strings.Join(lines, "\n")
}
