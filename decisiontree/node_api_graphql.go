package decisiontree

import "context"

func init() {
	MustRegisterNode(stageAPITestingGraphQL, isAPITestingGraphQLStage, runAPITestingGraphQL)
}

func isAPITestingGraphQLStage(input ThirdPartyInput) bool {
	return input.Stage == stageAPITestingGraphQL
}

func runAPITestingGraphQL(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	ip, err := requireString(input.Payload, "ip")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["ip"] = ip
	nextPayload["graphql_checked"] = true

	return ToolResult{
		ToolName: stageAPITestingGraphQL,
		Calls: []ToolCall{
			{Tool: "graphiql", Function: "SchemaIntrospection", Purpose: "enumerate graphql schema and operations"},
			{Tool: "burp-inql", Function: "RunGraphQLAudit", Purpose: "test graphql specific auth and data exposure flaws"},
		},
		Output: map[string]any{
			"next_stage":   stageAPITestingFuzzing,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
