// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

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
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["business_logic_tested"] = true
	nextPayload["workflow_manipulation_tested"] = true

	calls := []core.ToolCall{
		{Tool: "manual-tester", Function: "BypassWorkflowSteps", Purpose: "test skipped, repeated, and out-of-sequence workflow actions"},
		{Tool: "manual-tester", Function: "SubmitInvalidStateData", Purpose: "test server-side enforcement of business rules and validation"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingBusinessLogic,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageActiveTestingInputProbing,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
