// File overview:
// Active-testing stage node/constants for the decision tree. It structures exploit validation into small verifiable steps to reduce false positives and preserve traceability.

package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingInjection, isActiveTestingInjectionStage, runActiveTestingInjection)
}

func isActiveTestingInjectionStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingInjection
}

func runActiveTestingInjection(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["injection_tested"] = true
	nextPayload["path_traversal_tested"] = true

	calls := []core.ToolCall{
		{Tool: "burp-repeater", Function: "ProbeSQLAndCommandInjection", Purpose: "manually test sql and command injection indicators with harmless verification payloads"},
		{Tool: "burp-repeater", Function: "ProbePathTraversal", Purpose: "test path traversal safely using controlled non-sensitive file checks"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageActiveTestingInjection,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageActiveTestingErrorHandling,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
