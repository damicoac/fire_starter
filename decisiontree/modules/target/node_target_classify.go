// File overview:
// Target intake/classification stage logic. It exists to normalize initial scope data so downstream modules can assume valid and consistent target context.

package target

import (
	"context"

	"blackwater/decisiontree/core"
	apitesting "blackwater/decisiontree/features/api_testing"
)

func init() {
	core.MustRegisterNode(stageTargetClassify, isTargetClassifyStage, runTargetClassify)
}

func isTargetClassifyStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageTargetClassify
}

func runTargetClassify(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	hasAPI := core.GetBool(input.Payload, "has_api")
	nextStage := apitesting.StageComplete
	if hasAPI {
		nextStage = apitesting.StageRecon
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["has_api"] = hasAPI

	calls := []core.ToolCall{
		{Tool: "http-probe", Function: "DetectAPIService", Purpose: "detect api responses and api metadata"},
		{Tool: "service-fingerprint", Function: "ClassifyTarget", Purpose: "classify target workload"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	for _, execution := range executions {
		if execution.Tool == "http-probe" && execution.Function == "DetectAPIService" {
			if detected, ok := execution.Findings["api_detected"].(bool); ok {
				nextPayload["has_api"] = detected
				if detected {
					nextStage = apitesting.StageRecon
				} else {
					nextStage = apitesting.StageComplete
				}
			}
		}
	}

	return core.ToolResult{
		ToolName:   stageTargetClassify,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   nextStage,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
