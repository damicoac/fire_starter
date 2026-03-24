package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingRateLimit, isAPITestingRateLimitStage, runAPITestingRateLimit)
}

func isAPITestingRateLimitStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingRateLimit
}

func runAPITestingRateLimit(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["rate_limit_checked"] = true

	return ToolResult{
		ToolName: stageAPITestingRateLimit,
		Calls: []ToolCall{
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
