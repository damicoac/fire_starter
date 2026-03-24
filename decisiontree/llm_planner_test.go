package decisiontree

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeDecisionModel struct {
	response string
	err      error
	prompts  []string
}

func (m *fakeDecisionModel) Complete(ctx context.Context, prompt string) (string, error) {
	_ = ctx
	m.prompts = append(m.prompts, prompt)
	if m.err != nil {
		return "", m.err
	}
	return m.response, nil
}

func TestNewJSONLLMToolPlanner_Validation(t *testing.T) {
	_, err := NewJSONLLMToolPlanner(nil)
	if err == nil {
		t.Fatalf("expected nil model error")
	}

	planner, err := NewJSONLLMToolPlanner(&fakeDecisionModel{})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	if planner == nil {
		t.Fatalf("expected planner instance")
	}
}

func TestJSONLLMToolPlanner_DecideNextTool_Success(t *testing.T) {
	model := &fakeDecisionModel{response: `{"continue":true,"next_tool":"tool.two","next_payload":{"source":"llm"}}`}
	logMockData(t, "llm-planner model response", model.response)
	planner, err := NewJSONLLMToolPlanner(model)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	decision, err := planner.DecideNextTool(context.Background(), ToolResult{ToolName: "tool.one"}, []ToolDescriptor{{Name: "tool.one", Description: "first"}, {Name: "tool.two", Description: "second"}})
	if err != nil {
		t.Fatalf("unexpected decision error: %v", err)
	}
	if !decision.Continue {
		t.Fatalf("expected continue decision")
	}
	if decision.NextTool != "tool.two" {
		t.Fatalf("expected tool.two, got %q", decision.NextTool)
	}
	if decision.NextPayload["source"] != "llm" {
		t.Fatalf("expected llm payload, got %#v", decision.NextPayload)
	}
	if len(model.prompts) != 1 {
		t.Fatalf("expected one prompt call, got %d", len(model.prompts))
	}
	if !strings.Contains(model.prompts[0], `"available_tools"`) {
		t.Fatalf("expected available_tools in prompt, got %q", model.prompts[0])
	}
}

func TestJSONLLMToolPlanner_DecideNextTool_RequiresNextToolWhenContinuing(t *testing.T) {
	model := &fakeDecisionModel{response: `{"continue":true,"next_payload":{}}`}
	logMockData(t, "llm-planner missing-next-tool response", model.response)
	planner, err := NewJSONLLMToolPlanner(model)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	_, err = planner.DecideNextTool(context.Background(), ToolResult{ToolName: "tool.one"}, []ToolDescriptor{{Name: "tool.one"}})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "must include next_tool") {
		t.Fatalf("expected next_tool validation error, got %v", err)
	}
}

func TestJSONLLMToolPlanner_DecideNextTool_ModelError(t *testing.T) {
	expectedErr := errors.New("model failed")
	model := &fakeDecisionModel{err: expectedErr}
	planner, err := NewJSONLLMToolPlanner(model)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	_, err = planner.DecideNextTool(context.Background(), ToolResult{ToolName: "tool.one"}, []ToolDescriptor{{Name: "tool.one"}})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected model error, got %v", err)
	}
	if !strings.Contains(err.Error(), "get llm decision response") {
		t.Fatalf("expected wrapped model error, got %v", err)
	}
}

func TestBuildLLMDecisionPrompt(t *testing.T) {
	prompt, err := BuildLLMDecisionPrompt(
		ToolResult{ToolName: "tool.one", Output: map[string]any{"ok": true}},
		[]ToolDescriptor{{Name: "tool.one", Description: ""}, {Name: "tool.two", Description: "Second stage"}},
	)
	if err != nil {
		t.Fatalf("unexpected prompt error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(prompt), &parsed); err != nil {
		t.Fatalf("expected valid json prompt, got error: %v", err)
	}
	availableToolsAny, ok := parsed["available_tools"]
	if !ok {
		t.Fatalf("expected available_tools in prompt payload")
	}
	availableTools, ok := availableToolsAny.([]any)
	if !ok || len(availableTools) != 2 {
		t.Fatalf("unexpected available_tools payload: %#v", availableToolsAny)
	}
}
