package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingComplete, isAPITestingCompleteStage, runAPITestingComplete)
}

func isAPITestingCompleteStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingComplete
}

func runAPITestingComplete(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["api_testing_complete"] = true

	return core.ToolResult{
		ToolName: stageAPITestingComplete,
		Calls: []core.ToolCall{
			{Tool: "reporter", Function: "SummarizeAPIFindings", Purpose: "build final api security assessment"},
		},
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
