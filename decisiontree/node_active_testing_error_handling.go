package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingErrorHandling, isActiveTestingErrorHandlingStage, runActiveTestingErrorHandling)
}

func isActiveTestingErrorHandlingStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingErrorHandling
}

func runActiveTestingErrorHandling(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["error_handling_tested"] = true
	nextPayload["error_disclosure_reviewed"] = true

	return ToolResult{
		ToolName: stageActiveTestingErrorHandling,
		Calls: []ToolCall{
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
