package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingXSS, isActiveTestingXSSStage, runActiveTestingXSS)
}

func isActiveTestingXSSStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingXSS
}

func runActiveTestingXSS(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["xss_tested"] = true

	return ToolResult{
		ToolName: stageActiveTestingXSS,
		Calls: []ToolCall{
			{Tool: "burp-repeater", Function: "InjectXSSPayloads", Purpose: "inject xss payloads into observed request parameters"},
			{Tool: "manual-tester", Function: "AnalyzeReflectedAndStoredResponses", Purpose: "identify reflected and stored script execution vectors"},
		},
		Output: map[string]any{
			"next_stage":   stageActiveTestingInjection,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
