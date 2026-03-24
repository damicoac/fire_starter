package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingFuzzing, isAPITestingFuzzingStage, runAPITestingFuzzing)
}

func isAPITestingFuzzingStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingFuzzing
}

func runAPITestingFuzzing(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["fuzzing_checked"] = true

	return ToolResult{
		ToolName: stageAPITestingFuzzing,
		Calls: []ToolCall{
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
