package decisiontree

import "context"

func init() {
	MustRegisterNode(stageApplicationMappingExplore, isApplicationMappingExploreStage, runApplicationMappingExplore)
}

func isApplicationMappingExploreStage(input ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingExplore
}

func runApplicationMappingExplore(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	// Ensure the application target is available before exploration starts.
	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["manual_exploration_complete"] = true
	nextPayload["proxy_recording_complete"] = true

	return ToolResult{
		ToolName: stageApplicationMappingExplore,
		Calls: []ToolCall{
			{Tool: "browser", Function: "WalkApplicationFlows", Purpose: "manually traverse application features and multi-step workflows"},
			{Tool: "burp-suite", Function: "RecordProxyTraffic", Purpose: "capture requests and responses while browsing"},
		},
		Output: map[string]any{
			"next_stage":   stageApplicationMappingEntryPoints,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
