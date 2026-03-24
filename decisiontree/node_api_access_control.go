package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingAccess, isAPITestingAccessStage, runAPITestingAccess)
}

func isAPITestingAccessStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingAccess
}

func runAPITestingAccess(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["access_control_checked"] = true

	return ToolResult{
		ToolName: stageAPITestingAccess,
		Calls: []ToolCall{
			{Tool: "burp-suite", Function: "RunABATests", Purpose: "evaluate bola and bfla through role switching"},
			{Tool: "postman", Function: "ReplayPrivilegedRequests", Purpose: "check unauthorized access to functions and objects"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingRateLimit,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
