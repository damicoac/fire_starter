package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingComplete, isActiveTestingCompleteStage, runActiveTestingComplete)
}

func isActiveTestingCompleteStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingComplete
}

func runActiveTestingComplete(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["active_testing_complete"] = true

	return ToolResult{
		ToolName: stageActiveTestingComplete,
		Calls: []ToolCall{
			{Tool: "reporter", Function: "SummarizeActiveTestingFindings", Purpose: "produce final active testing summary and prioritized findings"},
		},
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
