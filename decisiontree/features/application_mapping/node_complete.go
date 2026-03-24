// File overview:
// Application-mapping stage node/constants for the decision tree. It exists to progressively build attack-surface knowledge before active exploitation checks begin.

package applicationmapping

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageApplicationMappingComplete, isApplicationMappingCompleteStage, runApplicationMappingComplete)
}

func isApplicationMappingCompleteStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingComplete
}

func runApplicationMappingComplete(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	// Confirm the module is operating against a known target.
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["application_mapping_complete"] = true

	calls := []core.ToolCall{
		{Tool: "reporter", Function: "SummarizeApplicationMapping", Purpose: "produce final application mapping and analysis summary"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageApplicationMappingComplete,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_payload": nextPayload,
			"continue":     false,
		},
	}, nil
}
