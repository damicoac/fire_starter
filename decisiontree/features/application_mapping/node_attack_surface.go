// File overview:
// Application-mapping stage node/constants for the decision tree. It exists to progressively build attack-surface knowledge before active exploitation checks begin.

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

	calls := []core.ToolCall{
		{Tool: "mapper", Function: "BuildAttackSurfaceMap", Purpose: "compile functional paths, entry points, and technologies into an attack surface map"},
		{Tool: "prioritizer", Function: "PrioritizeSensitiveFunctions", Purpose: "rank high-risk and sensitive application functionality for deeper testing"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageApplicationMappingAttackSurface,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
