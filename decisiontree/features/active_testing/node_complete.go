package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingComplete, isActiveTestingCompleteStage, runActiveTestingComplete)
}

func isActiveTestingCompleteStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingComplete
}

func runActiveTestingComplete(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["active_testing_complete"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingComplete,
		Calls: []core.ToolCall{
			{Tool: "reporter", Function: "SummarizeActiveTestingFindings", Purpose: "produce final active testing summary and prioritized findings"},
		},
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
