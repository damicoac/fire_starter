package applicationmapping

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageApplicationMappingExplore, isApplicationMappingExploreStage, runApplicationMappingExplore)
}

func isApplicationMappingExploreStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageApplicationMappingExplore
}

func runApplicationMappingExplore(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	// Ensure the application target is available before exploration starts.
	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["manual_exploration_complete"] = true
	nextPayload["proxy_recording_complete"] = true

	return core.ToolResult{
		ToolName: stageApplicationMappingExplore,
		Calls: []core.ToolCall{
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
