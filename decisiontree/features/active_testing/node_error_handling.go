package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingErrorHandling, isActiveTestingErrorHandlingStage, runActiveTestingErrorHandling)
}

func isActiveTestingErrorHandlingStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingErrorHandling
}

func runActiveTestingErrorHandling(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["error_handling_tested"] = true
	nextPayload["error_disclosure_reviewed"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingErrorHandling,
		Calls: []core.ToolCall{
			{Tool: "burp-repeater", Function: "TriggerErrorConditions", Purpose: "send malformed and boundary inputs to observe server-side error behavior"},
			{Tool: "manual-tester", Function: "InspectErrorLeakage", Purpose: "identify stack traces, internal paths, and implementation detail disclosure"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingConfigChecks,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
