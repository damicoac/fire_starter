// File overview:
// LLM planning adapter and strict JSON prompt/response handling. It exists to constrain model output into deterministic next-step decisions the runtime can safely execute.

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// LLMDecisionModel is the minimal model contract used to choose the next tool.
//
// The model receives a prompt string that includes:
//   - the last tool result,
//   - available tool names and descriptions,
//   - the expected JSON response schema.
//
// The model must return a JSON object consumable by JSONLLMToolPlanner.
type LLMDecisionModel interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// JSONLLMToolPlanner asks an LLM for the next-tool decision and parses the JSON answer.
//
// This makes the decision tree digestible for LLMs because the prompt always includes
// stable JSON structures and explicit output requirements.
type JSONLLMToolPlanner struct {
	model LLMDecisionModel
}

// NewJSONLLMToolPlanner validates and returns a planner wired to an LLM model.
func NewJSONLLMToolPlanner(model LLMDecisionModel) (*JSONLLMToolPlanner, error) {
	if model == nil {
		return nil, errors.New("llm decision model is required")
	}
	return &JSONLLMToolPlanner{model: model}, nil
}

// DecideNextTool builds a deterministic planning prompt and converts the model response
// into a normalized loop decision.
func (p *JSONLLMToolPlanner) DecideNextTool(ctx context.Context, result ToolResult, tools []ToolDescriptor) (NextToolDecision, error) {
	prompt, err := buildLLMDecisionPrompt(result, tools)
	if err != nil {
		return NextToolDecision{}, err
	}

	response, err := p.model.Complete(ctx, prompt)
	if err != nil {
		return NextToolDecision{}, fmt.Errorf("get llm decision response: %w", err)
	}

	var parsed llmDecisionResponse
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		return NextToolDecision{}, fmt.Errorf("decode llm decision response: %w", err)
	}
	if parsed.Continue && strings.TrimSpace(parsed.NextTool) == "" {
		return NextToolDecision{}, errors.New("llm response must include next_tool when continue is true")
	}

	nextPayload := map[string]any{}
	if parsed.NextPayload != nil {
		nextPayload = copyPayload(parsed.NextPayload)
	}

	return NextToolDecision{
		NextTool:    parsed.NextTool,
		NextPayload: nextPayload,
		Continue:    parsed.Continue,
	}, nil
}

// BuildLLMDecisionPrompt produces a structured JSON planning request for the model.
func BuildLLMDecisionPrompt(result ToolResult, tools []ToolDescriptor) (string, error) {
	return buildLLMDecisionPrompt(result, tools)
}

// buildLLMDecisionPrompt produces a structured JSON planning request for the model.
func buildLLMDecisionPrompt(result ToolResult, tools []ToolDescriptor) (string, error) {
	request := llmDecisionPrompt{
		Task: "Choose the next tool in the decision-tree loop using the provided last_tool_result and available_tools.",
		ResponseSchema: map[string]string{
			"continue":     "boolean",
			"next_tool":    "string (required when continue=true)",
			"next_payload": "object",
		},
		LastToolResult: result,
		AvailableTools: normalizeToolCatalog(tools),
	}

	encoded, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal llm decision prompt: %w", err)
	}
	return string(encoded), nil
}

// normalizeToolCatalog ensures each tool descriptor has a useful description for routing.
func normalizeToolCatalog(tools []ToolDescriptor) []ToolDescriptor {
	normalized := make([]ToolDescriptor, 0, len(tools))
	for _, tool := range tools {
		description := strings.TrimSpace(tool.Description)
		if description == "" {
			description = fmt.Sprintf("tool %s", tool.Name)
		}
		normalized = append(normalized, ToolDescriptor{
			Name:        tool.Name,
			Description: description,
		})
	}
	return normalized
}

// llmDecisionPrompt is a strict wire format sent to the model.
// A concrete struct is used instead of ad-hoc maps so required fields stay
// stable across refactors and prompt changes remain testable.
type llmDecisionPrompt struct {
	Task           string            `json:"task"`
	ResponseSchema map[string]string `json:"response_schema"`
	LastToolResult ToolResult        `json:"last_tool_result"`
	AvailableTools []ToolDescriptor  `json:"available_tools"`
}

// llmDecisionResponse is the minimal accepted planner output schema.
// Keeping this narrow intentionally limits model freedom to reduce ambiguous
// routing and prevent malformed continuation decisions.
type llmDecisionResponse struct {
	Continue    bool           `json:"continue"`
	NextTool    string         `json:"next_tool"`
	NextPayload map[string]any `json:"next_payload"`
}
