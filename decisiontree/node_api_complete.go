package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingComplete, isAPITestingCompleteStage, runAPITestingComplete)
}

func isAPITestingCompleteStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingComplete
}

func runAPITestingComplete(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["api_testing_complete"] = true

	return ToolResult{
		ToolName: stageAPITestingComplete,
		Calls: []ToolCall{
			{Tool: "reporter", Function: "SummarizeAPIFindings", Purpose: "build final api security assessment"},
		},
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
