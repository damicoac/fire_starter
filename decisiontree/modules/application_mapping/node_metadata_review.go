// File overview:
// Application-mapping stage node/constants for the decision tree. It exists to progressively build attack-surface knowledge before active exploitation checks begin.

package applicationmapping

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageApplicationMappingMetadata, isApplicationMappingMetadataStage, runApplicationMappingMetadata)
}

func isApplicationMappingMetadataStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingMetadata
}

func runApplicationMappingMetadata(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	// Require the target context so metadata analysis remains scoped.
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["metadata_review_complete"] = true
	nextPayload["client_code_review_complete"] = true

	calls := []core.ToolCall{
		{Tool: "source-review", Function: "InspectHTMLAndMetadata", Purpose: "review html source, comments, and metadata for exposed internal details"},
		{Tool: "javascript-review", Function: "InspectPublicJavaScript", Purpose: "identify sensitive APIs, legacy endpoints, and risky DOM logic"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageApplicationMappingMetadata,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageApplicationMappingAttackSurface,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
