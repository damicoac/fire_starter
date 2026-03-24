package decisiontree

import (
	"strings"
	"testing"
)

func TestBuildStagePrompt_APITestingStage(t *testing.T) {
	instructions, userPrompt, err := BuildStagePrompt(
		ThirdPartyInput{
			Stage: "api-testing.recon",
			Payload: map[string]any{
				"ip": "10.10.10.10",
			},
		},
		ToolResult{
			ToolName: "api-testing.recon",
			Calls: []ToolCall{
				{Tool: "kiterunner", Function: "ScanRoutes", Purpose: "discover routes"},
			},
			Output: map[string]any{
				"next_stage": "api-testing.access-control",
				"continue":   true,
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(instructions, "Current role for this stage: API security test strategist") {
		t.Fatalf("expected API role in instructions, got %q", instructions)
	}
	if !strings.Contains(userPrompt, "Execution context (JSON):") {
		t.Fatalf("expected execution context section, got %q", userPrompt)
	}
	if !strings.Contains(userPrompt, "\"stage\": \"api-testing.recon\"") {
		t.Fatalf("expected stage in context json, got %q", userPrompt)
	}
	if !strings.Contains(userPrompt, "\"Tool\": \"kiterunner\"") {
		t.Fatalf("expected tool calls in context json, got %q", userPrompt)
	}
}

func TestBuildStagePrompt_DefaultStagePlan(t *testing.T) {
	instructions, userPrompt, err := BuildStagePrompt(
		ThirdPartyInput{
			Stage: "custom.stage",
			Payload: map[string]any{
				"target": "demo",
			},
		},
		ToolResult{
			ToolName: "custom.stage",
			Output: map[string]any{
				"continue": false,
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(instructions, "Current role for this stage: Security workflow coordinator") {
		t.Fatalf("expected default role in instructions, got %q", instructions)
	}
	if !strings.Contains(userPrompt, "Return stage summary, next actions, and branch decision notes.") {
		t.Fatalf("expected default output requirement, got %q", userPrompt)
	}
}
