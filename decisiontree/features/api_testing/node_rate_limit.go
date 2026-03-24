// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingRateLimit, isAPITestingRateLimitStage, runAPITestingRateLimit)
}

func isAPITestingRateLimitStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingRateLimit
}

func runAPITestingRateLimit(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["rate_limit_checked"] = true

	calls := []core.ToolCall{
		{Tool: "wfuzz", Function: "BurstRequestFuzz", Purpose: "probe request throttling and bypasses"},
		{Tool: "zap", Function: "RunRateLimitScan", Purpose: "verify resource exhaustion controls"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingRateLimit,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingInjection,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
