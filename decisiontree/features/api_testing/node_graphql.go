// File overview:
// API-testing stage node/constants for the decision tree. This file encodes one bounded step so API security checks remain modular, reorderable, and easy to validate.

package apitesting

import (
	"context"

	"blackwater/decisiontree/core"
)

func init() {
	core.MustRegisterNode(stageAPITestingGraphQL, isAPITestingGraphQLStage, runAPITestingGraphQL)
}

func isAPITestingGraphQLStage(input core.ThirdPartyInput) bool {
	return input.Stage == stageAPITestingGraphQL
}

func runAPITestingGraphQL(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
	ip, err := core.RequireString(input.Payload, "ip")
	if err != nil {
		return core.ToolResult{}, err
	}

	nextPayload := core.CopyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["graphql_checked"] = true

	calls := []core.ToolCall{
		{Tool: "graphiql", Function: "SchemaIntrospection", Purpose: "enumerate graphql schema and operations"},
		{Tool: "burp-inql", Function: "RunGraphQLAudit", Purpose: "test graphql specific auth and data exposure flaws"},
	}
	executions := core.ExecuteToolCalls(ctx, input.Payload, calls)
	nextPayload["last_execution_summary"] = core.ExecutionSummary(executions)

	return core.ToolResult{
		ToolName:   stageAPITestingGraphQL,
		Calls:      calls,
		Executions: executions,
		Output: map[string]any{
			"next_stage":   stageAPITestingFuzzing,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
