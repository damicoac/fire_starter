package decisiontree

import "context"

func init() {
	MustRegisterNode(stageApplicationMappingComplete, isApplicationMappingCompleteStage, runApplicationMappingComplete)
}

func isApplicationMappingCompleteStage(input ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingComplete
}

func runApplicationMappingComplete(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	// Confirm the module is operating against a known target.
	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["application_mapping_complete"] = true

	return ToolResult{
		ToolName: stageApplicationMappingComplete,
		Calls: []ToolCall{
			{Tool: "reporter", Function: "SummarizeApplicationMapping", Purpose: "produce final application mapping and analysis summary"},
		},
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
