package decisiontree

import "context"

func init() {
	MustRegisterNode(stageApplicationMappingAttackSurface, isApplicationMappingAttackSurfaceStage, runApplicationMappingAttackSurface)
}

func isApplicationMappingAttackSurfaceStage(input ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingAttackSurface
}

func runApplicationMappingAttackSurface(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	// Preserve the target identity while producing prioritized attack surface output.
	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["attack_surface_mapped"] = true
	nextPayload["sensitive_functions_prioritized"] = true

	nextStage := stageApplicationMappingComplete
	if getBool(input.Payload, "expand_prioritization") {
		nextPayload["expanded_prioritization_complete"] = true
	}

	return ToolResult{
		ToolName: stageApplicationMappingAttackSurface,
		Calls: []ToolCall{
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
