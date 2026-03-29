// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

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
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["idor_tested"] = true
	nextPayload["access_control_tested"] = true

	calls := []core.ToolCall{
		{Tool: "burp-repeater", Function: "ManipulateIdentifiers", Purpose: "test idor by swapping object and user identifiers in captured requests"},
		{Tool: "manual-tester", Function: "EnumerateProtectedResources", Purpose: "systematically verify resource access boundaries"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingAccessControl,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageActiveTestingBusinessLogic,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
