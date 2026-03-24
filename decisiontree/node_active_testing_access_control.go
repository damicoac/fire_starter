package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingAccessControl, isActiveTestingAccessControlStage, runActiveTestingAccessControl)
}

func isActiveTestingAccessControlStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingAccessControl
}

func runActiveTestingAccessControl(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["idor_tested"] = true
	nextPayload["access_control_tested"] = true

	return ToolResult{
		ToolName: stageActiveTestingAccessControl,
		Calls: []ToolCall{
			{Tool: "burp-repeater", Function: "ManipulateIdentifiers", Purpose: "test idor by swapping object and user identifiers in captured requests"},
			{Tool: "manual-tester", Function: "EnumerateProtectedResources", Purpose: "systematically verify resource access boundaries"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingBusinessLogic,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
