package decisiontree

import "context"

func init() {
	MustRegisterNode(stageApplicationMappingMetadata, isApplicationMappingMetadataStage, runApplicationMappingMetadata)
}

func isApplicationMappingMetadataStage(input ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingMetadata
}

func runApplicationMappingMetadata(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	// Require the target context so metadata analysis remains scoped.
	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["metadata_review_complete"] = true
	nextPayload["client_code_review_complete"] = true

	return ToolResult{
		ToolName: stageApplicationMappingMetadata,
		Calls: []ToolCall{
			{Tool: "source-review", Function: "InspectHTMLAndMetadata", Purpose: "review html source, comments, and metadata for exposed internal details"},
			{Tool: "javascript-review", Function: "InspectPublicJavaScript", Purpose: "identify sensitive APIs, legacy endpoints, and risky DOM logic"},
		},
		Output: map[string]any{
			"next_stage":   stageApplicationMappingAttackSurface,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
