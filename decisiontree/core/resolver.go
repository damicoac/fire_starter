package core

import "context"

func DefaultNextInputResolver(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
	_ = ctx

	nextStage, _ := result.Output["next_stage"].(string)
	continueFlow := false
	if value, ok := result.Output["continue"].(bool); ok {
		continueFlow = value
	}

	nextPayload := map[string]any{}
	if payload, ok := result.Output["next_payload"].(map[string]any); ok {
		nextPayload = payload
	}

	return ThirdPartyInput{Stage: nextStage, Payload: nextPayload}, continueFlow, nil
}
