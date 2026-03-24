// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingComplete, isAPITestingCompleteStage, runAPITestingComplete)
}

func isAPITestingCompleteStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingComplete
}

func runAPITestingComplete(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["api_testing_complete"] = true

	calls := []core.ToolCall{
		{Tool: "reporter", Function: "SummarizeAPIFindings", Purpose: "build final api security assessment"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingComplete,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
