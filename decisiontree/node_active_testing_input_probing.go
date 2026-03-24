package decisiontree

import "context"

func init() {
	MustRegisterNode(stageActiveTestingInputProbing, isActiveTestingInputProbingStage, runActiveTestingInputProbing)
}

func isActiveTestingInputProbingStage(input ThirdPartyInput) bool {
	return input.Stage == stageActiveTestingInputProbing
}

func runActiveTestingInputProbing(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["input_probing_complete"] = true
	nextPayload["low_rate_testing_enforced"] = true

	nextStage := stageActiveTestingXSS
	testXSS := true
	if value, ok := input.Payload["test_xss"].(bool); ok {
		testXSS = value
	}
	if !testXSS {
		nextPayload["xss_skipped"] = true
		nextStage = stageActiveTestingInjection
	}

	return ToolResult{
		ToolName: stageActiveTestingInputProbing,
		Calls: []ToolCall{
			{Tool: "manual-tester", Function: "CraftInputPayloads", Purpose: "probe collected input vectors with controlled payloads"},
			{Tool: "burp-intruder", Function: "LowRateSingleParameterMode", Purpose: "run controlled low-rate payload tests on one parameter at a time"},
		},
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
