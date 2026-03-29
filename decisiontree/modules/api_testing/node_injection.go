// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

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
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["injection_checked"] = true

	calls := []core.ToolCall{
		{Tool: "burp-suite", Function: "RunInjectionChecks", Purpose: "test sql nosql and command injection vectors"},
		{Tool: "nikto", Function: "AuditMisconfigurations", Purpose: "detect insecure api server configurations"},
		{Tool: "postman", Function: "JWTAbuseChecks", Purpose: "test authentication token handling flaws"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingInjection,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingGraphQL,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
