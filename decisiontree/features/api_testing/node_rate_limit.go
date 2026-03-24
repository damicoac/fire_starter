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
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["rate_limit_checked"] = true

	return core.ToolResult{
		ToolName: stageAPITestingRateLimit,
		Calls: []core.ToolCall{
			{Tool: "wfuzz", Function: "BurstRequestFuzz", Purpose: "probe request throttling and bypasses"},
			{Tool: "zap", Function: "RunRateLimitScan", Purpose: "verify resource exhaustion controls"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingInjection,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
