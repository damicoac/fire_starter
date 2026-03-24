package decisiontree

import "context"

func init() {
	MustRegisterNode(stageApplicationMappingEntryPoints, isApplicationMappingEntryPointsStage, runApplicationMappingEntryPoints)
}

func isApplicationMappingEntryPointsStage(input ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingEntryPoints
}

func runApplicationMappingEntryPoints(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	// Keep the target in the payload for downstream stages.
	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["entry_points_identified"] = true
	nextPayload["technology_fingerprinted"] = true

	return ToolResult{
		ToolName: stageApplicationMappingEntryPoints,
		Calls: []ToolCall{
			{Tool: "burp-suite", Function: "EnumerateInputVectors", Purpose: "identify query, body, header, and cookie entry points"},
			{Tool: "fingerprinter", Function: "IdentifyTechnologyStack", Purpose: "infer web server and framework technologies from observed traffic"},
		},
		Output: map[string]any{
			"next_stage":   stageApplicationMappingMetadata,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
