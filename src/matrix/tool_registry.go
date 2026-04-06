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
		description := fmt.Sprintf(
			"Use Case: %s\nFunction: %s\nProblem Solved: %s\nContext: Select this tool when applicable for lateral movement and the recon, probe, test, repeat loop. Feel free to use this dynamically as needed. Note that state/cookies are persisted automatically.",
			decision.UseCase, decision.Function, decision.ProblemTheToolSolves,
		)

		tool := ToolDefinition{
			Name:        name,
			Description: description,
			Identifier:  decision.Identifier,
			Technique:   decision.Technique,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload": map[string]any{
						"type":        "object",
						"description": "Execution context or target parameters for the selected module (e.g. url, target, etc.). Cookies/State are handled automatically.",
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
