package activetesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageActiveTestingXSS, isActiveTestingXSSStage, runActiveTestingXSS)
}

func isActiveTestingXSSStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingXSS
}

func runActiveTestingXSS(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	target, err := core.RequireString(input.Payload, "target")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["xss_tested"] = true

	return core.ToolResult{
		ToolName: stageActiveTestingXSS,
		Calls: []core.ToolCall{
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
