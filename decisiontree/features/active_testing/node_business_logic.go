package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingBusinessLogic, isActiveTestingBusinessLogicStage, runActiveTestingBusinessLogic)
}

func isActiveTestingBusinessLogicStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingBusinessLogic
}

func runActiveTestingBusinessLogic(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["business_logic_tested"] = true
	nextPayload["workflow_manipulation_tested"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingBusinessLogic,
		Calls: []core.ToolCall{
			{Tool: "manual-tester", Function: "BypassWorkflowSteps", Purpose: "test skipped, repeated, and out-of-sequence workflow actions"},
			{Tool: "manual-tester", Function: "SubmitInvalidStateData", Purpose: "test server-side enforcement of business rules and validation"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingInputProbing,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
