package core

import (
	"context"
	"testing"
)

func TestExecuteToolCall_ParseIP(t *testing.T) {
	result := ExecuteToolCall(context.Background(), map[string]any{"ip": "127.0.0.1"}, ToolCall{Tool: "input", Function: "parseIP", Purpose: "validate ip"})
	if !result.Success {
		t.Fatalf("expected successful execution, got error: %s", result.Error)
	}
	if valid, ok := result.Findings["is_valid_ip"].(bool); !ok || !valid {
		t.Fatalf("expected valid IP finding, got %#v", result.Findings)
	}
}

func TestExecuteToolCall_DetectAPIService(t *testing.T) {
	result := ExecuteToolCall(context.Background(), map[string]any{"target": "https://api.example.local", "has_api": true}, ToolCall{Tool: "http-probe", Function: "DetectAPIService", Purpose: "detect api"})
	if !result.Success {
		t.Fatalf("expected successful execution, got error: %s", result.Error)
	}
	apiDetected, ok := result.Findings["api_detected"].(bool)
	if !ok || !apiDetected {
		t.Fatalf("expected api_detected true, got %#v", result.Findings)
	}
}

func TestExecutionSummary(t *testing.T) {
	summary := ExecutionSummary([]ToolExecution{
		{Tool: "a", Function: "f1", Success: true},
		{Tool: "b", Function: "f2", Success: false, Error: "failed"},
	})
	if summary["total"] != 2 {
		t.Fatalf("expected total 2, got %#v", summary)
	}
	if summary["successful"] != 1 {
		t.Fatalf("expected successful 1, got %#v", summary)
	}
	if summary["failed"] != 1 {
		t.Fatalf("expected failed 1, got %#v", summary)
	}
}

func TestExecuteToolCall_EnumerateInputVectors(t *testing.T) {
	result := ExecuteToolCall(context.Background(), map[string]any{"target": "https://app.example.local"}, ToolCall{Tool: "burp-suite", Function: "EnumerateInputVectors", Purpose: "discover vectors"})
	if !result.Success {
		t.Fatalf("expected successful execution, got error: %s", result.Error)
	}
	vectors, ok := result.Findings["input_vectors"].([]string)
	if !ok || len(vectors) == 0 {
		t.Fatalf("expected discovered input vectors, got %#v", result.Findings)
	}
}

func TestExecuteToolCall_OptionsMethodDiscovery(t *testing.T) {
	result := ExecuteToolCall(context.Background(), map[string]any{"target": "https://app.example.local"}, ToolCall{Tool: "burp-repeater", Function: "SendOptionsRequests", Purpose: "discover methods"})
	if !result.Success {
		t.Fatalf("expected successful execution, got error: %s", result.Error)
	}
	methods, ok := result.Findings["allowed_methods"].([]string)
	if !ok || len(methods) == 0 {
		t.Fatalf("expected allowed methods, got %#v", result.Findings)
	}
}

func TestExecuteToolCall_SummarizeActiveTestingFindings(t *testing.T) {
	payload := map[string]any{
		"target":                   "https://app.example.local",
		"idor_tested":              true,
		"business_logic_tested":    true,
		"input_probing_complete":   true,
		"injection_tested":         true,
		"error_handling_tested":    true,
		"admin_interfaces_checked": true,
		"http_methods_checked":     true,
	}
	result := ExecuteToolCall(context.Background(), payload, ToolCall{Tool: "reporter", Function: "SummarizeActiveTestingFindings", Purpose: "summarize active testing"})
	if !result.Success {
		t.Fatalf("expected successful execution, got error: %s", result.Error)
	}
	score, ok := result.Findings["coverage_score"].(int)
	if !ok {
		t.Fatalf("expected integer coverage score, got %#v", result.Findings)
	}
	if score < 80 {
		t.Fatalf("expected high coverage score, got %d", score)
	}
}
