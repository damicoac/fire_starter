package applicationmapping

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageApplicationMappingAttackSurface, isApplicationMappingAttackSurfaceStage, runApplicationMappingAttackSurface)
}

func isApplicationMappingAttackSurfaceStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingAttackSurface
}

func runApplicationMappingAttackSurface(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	// Preserve the target identity while producing prioritized attack surface output.
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["attack_surface_mapped"] = true
	nextPayload["sensitive_functions_prioritized"] = true

	nextStage := stageApplicationMappingComplete
	if core.GetBool(input.Payload, "expand_prioritization") {
		nextPayload["expanded_prioritization_complete"] = true
	}

	return core.ToolResult{
		ToolName: stageApplicationMappingAttackSurface,
		Calls: []core.ToolCall{
			{Tool: "mapper", Function: "BuildAttackSurfaceMap", Purpose: "compile functional paths, entry points, and technologies into an attack surface map"},
			{Tool: "prioritizer", Function: "PrioritizeSensitiveFunctions", Purpose: "rank high-risk and sensitive application functionality for deeper testing"},
		},
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
