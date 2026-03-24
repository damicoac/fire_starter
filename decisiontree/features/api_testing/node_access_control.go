// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingAccess, isAPITestingAccessStage, runAPITestingAccess)
}

func isAPITestingAccessStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingAccess
}

func runAPITestingAccess(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["access_control_checked"] = true

	calls := []core.ToolCall{
		{Tool: "burp-suite", Function: "RunABATests", Purpose: "evaluate bola and bfla through role switching"},
		{Tool: "postman", Function: "ReplayPrivilegedRequests", Purpose: "check unauthorized access to functions and objects"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingAccess,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingRateLimit,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
