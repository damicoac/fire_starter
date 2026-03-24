package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingConfigChecks, isActiveTestingConfigChecksStage, runActiveTestingConfigChecks)
}

func isActiveTestingConfigChecksStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingConfigChecks
}

func runActiveTestingConfigChecks(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["admin_interfaces_checked"] = true
	nextPayload["http_methods_checked"] = true

	return ToolResult{
		ToolName: stageActiveTestingConfigChecks,
		Calls: []ToolCall{
			{Tool: "manual-tester", Function: "CheckPublicAdminInterfaces", Purpose: "verify whether administrative interfaces are publicly reachable"},
			{Tool: "burp-repeater", Function: "SendOptionsRequests", Purpose: "identify allowed http methods with controlled options requests"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingComplete,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
