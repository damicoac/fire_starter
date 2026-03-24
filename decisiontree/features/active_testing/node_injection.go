package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingInjection, isActiveTestingInjectionStage, runActiveTestingInjection)
}

func isActiveTestingInjectionStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingInjection
}

func runActiveTestingInjection(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["injection_tested"] = true
	nextPayload["path_traversal_tested"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingInjection,
		Calls: []core.ToolCall{
			{Tool: "burp-repeater", Function: "ProbeSQLAndCommandInjection", Purpose: "manually test sql and command injection indicators with harmless verification payloads"},
			{Tool: "burp-repeater", Function: "ProbePathTraversal", Purpose: "test path traversal safely using controlled non-sensitive file checks"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingErrorHandling,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
