// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingComplete, isActiveTestingCompleteStage, runActiveTestingComplete)
}

func isActiveTestingCompleteStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingComplete
}

func runActiveTestingComplete(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["active_testing_complete"] = true

	calls := []core.ToolCall{
		{Tool: "reporter", Function: "SummarizeActiveTestingFindings", Purpose: "produce final active testing summary and prioritized findings"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingComplete,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
