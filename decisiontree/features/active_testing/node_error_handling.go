// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingErrorHandling, isActiveTestingErrorHandlingStage, runActiveTestingErrorHandling)
}

func isActiveTestingErrorHandlingStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingErrorHandling
}

func runActiveTestingErrorHandling(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["error_handling_tested"] = true
	nextPayload["error_disclosure_reviewed"] = true

	calls := []core.ToolCall{
		{Tool: "burp-repeater", Function: "TriggerErrorConditions", Purpose: "send malformed and boundary inputs to observe server-side error behavior"},
		{Tool: "manual-tester", Function: "InspectErrorLeakage", Purpose: "identify stack traces, internal paths, and implementation detail disclosure"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingErrorHandling,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageActiveTestingConfigChecks,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
