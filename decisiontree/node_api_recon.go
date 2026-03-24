package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingRecon, isAPITestingReconStage, runAPITestingRecon)
}

func isAPITestingReconStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingRecon
}

func runAPITestingRecon(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["recon_complete"] = true

	return ToolResult{
		ToolName: stageAPITestingRecon,
		Calls: []ToolCall{
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
