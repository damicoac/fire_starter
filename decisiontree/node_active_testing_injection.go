package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingInjection, isActiveTestingInjectionStage, runActiveTestingInjection)
}

func isActiveTestingInjectionStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingInjection
}

func runActiveTestingInjection(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["injection_tested"] = true
	nextPayload["path_traversal_tested"] = true

	return ToolResult{
		ToolName: stageActiveTestingInjection,
		Calls: []ToolCall{
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
