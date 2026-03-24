package decisiontree

import (
	"context"
	"fmt"
	"net"
)

func init() {
	MustRegisterNode(stageTargetReceived, isTargetReceivedStage, runTargetReceived)
}

func isTargetReceivedStage(input ThirdPartyInput) bool {
	return input.Stage == stageTargetReceived
}

func runTargetReceived(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}
	if net.ParseIP(ip) == nil {
		return ToolResult{}, fmt.Errorf("invalid ip address %q", ip)
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip

	return ToolResult{
		ToolName: stageTargetReceived,
		Calls: []ToolCall{
			{Tool: "input", Function: "parseIP", Purpose: "validate target ip syntax"},
		},
		Output: map[string]any{
			"next_stage":   stageTargetClassify,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
