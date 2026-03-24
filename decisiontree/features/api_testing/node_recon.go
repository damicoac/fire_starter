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
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["recon_complete"] = true

	return core.ToolResult{
		ToolName: stageAPITestingRecon,
		Calls: []core.ToolCall{
			{Tool: "owasp-amass", Function: "EnumerateEndpoints", Purpose: "discover api endpoints and related assets"},
			{Tool: "kiterunner", Function: "ScanRoutes", Purpose: "discover hidden api paths and parameters"},
			{Tool: "arjun", Function: "DiscoverParameters", Purpose: "identify accepted api parameters"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingAccess,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
