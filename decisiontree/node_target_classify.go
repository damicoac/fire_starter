package decisiontree

import "context"

func init() {
	MustRegisterNode(stageTargetClassify, isTargetClassifyStage, runTargetClassify)
}

func isTargetClassifyStage(input ThirdPartyInput) bool {
	return input.Stage == stageTargetClassify
}

func runTargetClassify(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	hasAPI := getBool(input.Payload, "has_api")
	nextStage := stageAPITestingComplete
	if hasAPI {
		nextStage = stageAPITestingRecon
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["has_api"] = hasAPI

	return ToolResult{
		ToolName: stageTargetClassify,
		Calls: []ToolCall{
			{Tool: "http-probe", Function: "DetectAPIService", Purpose: "detect api responses and api metadata"},
			{Tool: "service-fingerprint", Function: "ClassifyTarget", Purpose: "classify target workload"},
		},
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
