// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingFuzzing, isAPITestingFuzzingStage, runAPITestingFuzzing)
}

func isAPITestingFuzzingStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingFuzzing
}

func runAPITestingFuzzing(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["fuzzing_checked"] = true

	calls := []core.ToolCall{
		{Tool: "wfuzz", Function: "FuzzWide", Purpose: "test many api parameters with baseline payloads"},
		{Tool: "wfuzz", Function: "FuzzDeep", Purpose: "stress high-risk parameters with focused payload sets"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingFuzzing,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingComplete,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
