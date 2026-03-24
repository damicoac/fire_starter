package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingInjection, isAPITestingInjectionStage, runAPITestingInjection)
}

func isAPITestingInjectionStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingInjection
}

func runAPITestingInjection(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["injection_checked"] = true

	return core.ToolResult{
		ToolName: stageAPITestingInjection,
		Calls: []core.ToolCall{
			{Tool: "burp-suite", Function: "RunInjectionChecks", Purpose: "test sql nosql and command injection vectors"},
			{Tool: "nikto", Function: "AuditMisconfigurations", Purpose: "detect insecure api server configurations"},
			{Tool: "postman", Function: "JWTAbuseChecks", Purpose: "test authentication token handling flaws"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingGraphQL,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
