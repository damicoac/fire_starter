// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingConfigChecks, isActiveTestingConfigChecksStage, runActiveTestingConfigChecks)
}

func isActiveTestingConfigChecksStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingConfigChecks
}

func runActiveTestingConfigChecks(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["admin_interfaces_checked"] = true
	nextPayload["http_methods_checked"] = true

	calls := []core.ToolCall{
		{Tool: "manual-tester", Function: "CheckPublicAdminInterfaces", Purpose: "verify whether administrative interfaces are publicly reachable"},
		{Tool: "burp-repeater", Function: "SendOptionsRequests", Purpose: "identify allowed http methods with controlled options requests"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingConfigChecks,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageActiveTestingComplete,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
