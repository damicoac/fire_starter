// File overview:
// Target intake/classification stage logic. It exists to normalize initial scope data so downstream modules can assume valid and consistent target context.

package target

import (
	"blackwater/decisiontree/core"
	"context"
	"fmt"
	"net"
)

func init() {
	core.MustRegisterNode(stageTargetReceived, isTargetReceivedStage, runTargetReceived)
}

func isTargetReceivedStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageTargetReceived
}

func runTargetReceived(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	_ = ctx

	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}
	if net.ParseIP(ip) == nil {
		return core.ToolResult{}, fmt.Errorf("invalid ip address %q", ip)
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip

	calls := []core.ToolCall{
		{Tool: "input", Function: "parseIP", Purpose: "validate target ip syntax"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)

	return core.ToolResult{
		ToolName:   stageTargetReceived,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageTargetClassify,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
