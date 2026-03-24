package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingBusinessLogic, isActiveTestingBusinessLogicStage, runActiveTestingBusinessLogic)
}

func isActiveTestingBusinessLogicStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingBusinessLogic
}

func runActiveTestingBusinessLogic(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["business_logic_tested"] = true
	nextPayload["workflow_manipulation_tested"] = true

	return ToolResult{
		ToolName: stageActiveTestingBusinessLogic,
		Calls: []ToolCall{
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
