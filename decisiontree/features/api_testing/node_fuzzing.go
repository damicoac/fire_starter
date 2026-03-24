package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingFuzzing, isAPITestingFuzzingStage, runAPITestingFuzzing)
}

func isAPITestingFuzzingStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingFuzzing
}

func runAPITestingFuzzing(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["fuzzing_checked"] = true

	return core.ToolResult{
		ToolName: stageAPITestingFuzzing,
		Calls: []core.ToolCall{
			{Tool: "wfuzz", Function: "FuzzWide", Purpose: "test many api parameters with baseline payloads"},
			{Tool: "wfuzz", Function: "FuzzDeep", Purpose: "stress high-risk parameters with focused payload sets"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingComplete,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
