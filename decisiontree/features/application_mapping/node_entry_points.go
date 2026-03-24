package applicationmapping

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageApplicationMappingEntryPoints, isApplicationMappingEntryPointsStage, runApplicationMappingEntryPoints)
}

func isApplicationMappingEntryPointsStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingEntryPoints
}

func runApplicationMappingEntryPoints(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	// Keep the target in the payload for downstream stages.
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["entry_points_identified"] = true
	nextPayload["technology_fingerprinted"] = true

	return core.ToolResult{
		ToolName: stageApplicationMappingEntryPoints,
		Calls: []core.ToolCall{
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
