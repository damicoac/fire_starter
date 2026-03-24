// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingInputProbing, isActiveTestingInputProbingStage, runActiveTestingInputProbing)
}

func isActiveTestingInputProbingStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingInputProbing
}

func runActiveTestingInputProbing(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["input_probing_complete"] = true
	nextPayload["low_rate_testing_enforced"] = true

	nextStage := stageActiveTestingXSS
	testXSS := true
	if value, ok := input.Payload["test_xss"].(bool); ok {
		testXSS = value
	}
	if !testXSS {
		nextPayload["xss_skipped"] = true
		nextStage = stageActiveTestingInjection
	}

	calls := []core.ToolCall{
		{Tool: "manual-tester", Function: "CraftInputPayloads", Purpose: "probe collected input vectors with controlled payloads"},
		{Tool: "burp-intruder", Function: "LowRateSingleParameterMode", Purpose: "run controlled low-rate payload tests on one parameter at a time"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingInputProbing,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
