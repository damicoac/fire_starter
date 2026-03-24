package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingAccessControl, isActiveTestingAccessControlStage, runActiveTestingAccessControl)
}

func isActiveTestingAccessControlStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingAccessControl
}

func runActiveTestingAccessControl(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["idor_tested"] = true
	nextPayload["access_control_tested"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingAccessControl,
		Calls: []core.ToolCall{
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
