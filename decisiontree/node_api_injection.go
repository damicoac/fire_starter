package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingInjection, isAPITestingInjectionStage, runAPITestingInjection)
}

func isAPITestingInjectionStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingInjection
}

func runAPITestingInjection(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["injection_checked"] = true

	return ToolResult{
		ToolName: stageAPITestingInjection,
		Calls: []ToolCall{
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
