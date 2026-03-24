// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingRecon, isAPITestingReconStage, runAPITestingRecon)
}

func isAPITestingReconStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingRecon
}

func runAPITestingRecon(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["recon_complete"] = true

	calls := []core.ToolCall{
		{Tool: "owasp-amass", Function: "EnumerateEndpoints", Purpose: "discover api endpoints and related assets"},
		{Tool: "kiterunner", Function: "ScanRoutes", Purpose: "discover hidden api paths and parameters"},
		{Tool: "arjun", Function: "DiscoverParameters", Purpose: "identify accepted api parameters"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingRecon,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingAccess,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
