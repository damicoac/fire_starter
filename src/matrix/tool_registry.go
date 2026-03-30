package matrix

import (
	"fmt"
	"sort"
	"strings"
)

type ToolRegistry struct {
	byIdentifier map[string]ToolDefinition
	sortedTools  []ToolDefinition
}

func NewToolRegistry(decisions []Decision) *ToolRegistry {
	byIdentifier := make(map[string]ToolDefinition, len(decisions))
	tools := make([]ToolDefinition, 0, len(decisions))

	for _, decision := range decisions {
		name := toolNameFromDecision(decision)
		tool := ToolDefinition{
			Name:        name,
			Description: decision.ProblemTheToolSolves,
			Identifier:  decision.Identifier,
			Technique:   decision.Technique,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload": map[string]any{
						"type":        "object",
						"description": "Execution context for the selected module.",
					},
				},
				"required": []string{},
			},
		}

		byIdentifier[decision.Identifier] = tool
		tools = append(tools, tool)
	}

	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Identifier < tools[j].Identifier
	})

	return &ToolRegistry{
		byIdentifier: byIdentifier,
		sortedTools:  tools,
	}
}

func (r *ToolRegistry) ListTools() []ToolDefinition {
	result := make([]ToolDefinition, len(r.sortedTools))
	copy(result, r.sortedTools)
	return result
}

func (r *ToolRegistry) ToolForIdentifier(identifier string) (ToolDefinition, bool) {
	tool, ok := r.byIdentifier[identifier]
	return tool, ok
}

func toolNameFromDecision(decision Decision) string {
	normalized := strings.ToLower(decision.Technique)
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	builder := strings.Builder{}
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			builder.WriteRune(r)
		}
	}
	name := strings.Trim(builder.String(), "_")
	if name == "" {
		name = fmt.Sprintf("decision_%s", decision.Identifier)
	}
	return fmt.Sprintf("decision_%s", name)
}
