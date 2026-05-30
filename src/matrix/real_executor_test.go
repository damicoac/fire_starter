package matrix

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRealExecutor_OSCommandInjection(t *testing.T) {
	// Start a mock server
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Just return success for reflection detection if needed
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "uid=1000(test) gid=1000(test) groups=1000(test)")
	}))
	defer ts.Close()

	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}
	decision := Decision{
		Identifier: "10",
		Technique:  "os_command_injection",
		Payload: map[string]any{
			"ip":        "127.0.0.1",
			"url":       ts.URL,
			"threads":   10,
			"threshold": 1,
		},
	}

	output, err := executor.Execute(decision)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, "os_command_injection_results") {
		t.Errorf("Output does not contain os_command_injection_results: %s", output)
	}

	if requestCount == 0 {
		t.Error("Mock server did not receive any requests")
	}
}

func TestMapTechniqueToStage(t *testing.T) {
	tests := []struct {
		technique string
		expected  Phase
	}{
		{"google_dorking", PhaseReconnaissance},
		{"subdomain_enumeration", PhaseReconnaissance},
		{"port_scanning", PhaseScanning},
		{"error_message", PhaseScanning},
		{"idor", PhaseVulnerabilityAnalysis},
		{"sql_injection", PhaseExploitation},
		{"cross_site_scripting", PhaseExploitation},
		{"rate_limit", PhaseVulnerabilityAnalysis},
		{"unknown_technique", PhaseReconnaissance},
	}

	for _, tt := range tests {
		t.Run(tt.technique, func(t *testing.T) {
			got := MapTechniqueToStage(tt.technique)
			if got != string(tt.expected) {
				t.Errorf("MapTechniqueToStage(%q) = %q, want %q", tt.technique, got, tt.expected)
			}
		})
	}
}

func TestRealExecutor_ServerSideTemplateInjectionSsti(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "test")
	}))
	defer ts.Close()

	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	decision := Decision{
		Technique: "server_side_template_injection_ssti",
		Payload: map[string]any{
			"ip":      "127.0.0.1",
			"url":     ts.URL,
			"threads": 10,
		},
	}

	output, err := executor.Execute(decision)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, "server_side_template_injection_ssti_results") {
		t.Errorf("Output does not contain server_side_template_injection_ssti_results: %s", output)
	}
}

func TestRealExecutor_PathTraversalAttack(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "test")
	}))
	defer ts.Close()

	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	decision := Decision{
		Technique: "path_traversal_attack",
		Payload: map[string]any{
			"ip":      "127.0.0.1",
			"url":     ts.URL,
			"threads": 10,
		},
	}

	output, err := executor.Execute(decision)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, "path_traversal_attack_results") {
		t.Errorf("Output does not contain path_traversal_attack_results: %s", output)
	}
}

func TestRealExecutor_TechniqueMatching(t *testing.T) {
	executor, _ := NewRealExecutor([]Decision{})

	// 'json_hijacking' vs 'json_hijacking_test'
	decision1 := Decision{
		Identifier: "1",
		Technique:  "json_hijacking",
		Payload:    map[string]any{"url": "http://127.0.0.1"},
	}
	output1, _ := executor.Execute(decision1)
	if strings.Contains(output1, "JsonHijackingTest") {
		t.Errorf("Expected json_hijacking to NOT match json_hijacking_test, but it did.")
	}

	// 'google_dorking' vs 'google_dorking_for_apis'
	decision2 := Decision{
		Identifier: "2",
		Technique:  "google_dorking",
		Payload:    map[string]any{"url": "http://127.0.0.1"},
	}
	output2, _ := executor.Execute(decision2)
	if strings.Contains(output2, "GoogleDorkingForApis") {
		t.Errorf("Expected google_dorking to NOT match google_dorking_for_apis, but it did.")
	}
}
func TestRealExecutor_ServerSideTemplateInjectionSsti_OOB(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "http://") {
			// Extract and call the OOB URL
			start := strings.Index(q, "http://")
			end := start
			for end < len(q) && q[end] != ' ' && q[end] != ')' && q[end] != '\'' && q[end] != '"' && q[end] != '}' {
				end++
			}
			oobURL := q[start:end]
			_, _ = http.Get(oobURL)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OOB simulated")
	}))
	defer ts.Close()

	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	decision := Decision{
		Technique: "server_side_template_injection_ssti",
		Payload: map[string]any{
			"ip":      "127.0.0.1",
			"url":     ts.URL + "?q=test", // Providing a vector to avoid default 3 vectors
			"threads": 5,
		},
	}

	output, err := executor.Execute(decision)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(strings.ToLower(output), "oob") || !strings.Contains(strings.ToLower(output), "vulnerable") {
		t.Errorf("Output does not contain OOB vulnerability: %s", output)
	}
}

func TestRealExecutor_ExecuteReal(t *testing.T) {
	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	// ExecuteReal
	decision := Decision{Technique: "unknown_technique", Payload: map[string]any{"ip": "10.0.0.1"}}
	output, err := executor.ExecuteReal(decision, decision.Payload, func(s string) {})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "unknown_technique") {
		t.Errorf("unexpected output: %s", output)
	}
}

func TestRealExecutor_ExecuteMissingTarget(t *testing.T) {
	executor, err := NewRealExecutor([]Decision{})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	decision := Decision{Technique: "unknown_technique"}
	_, err = executor.ExecuteReal(decision, nil, func(s string) {})
	if err == nil {
		t.Error("expected error for missing target")
	}
}

func TestRealExecutor_ExecuteByToolName(t *testing.T) {
	decisions := []Decision{
		{Identifier: "test_tool", Technique: "unknown_technique", UseCase: "testing"},
	}
	registry := NewToolRegistry(decisions)

	executor := &RealExecutor{
		registry: registry,
		toolByName: map[string]ToolDefinition{
			"test_tool_name": registry.ListTools()[0],
		},
	}

	// Valid execution
	_, err := executor.ExecuteByToolName("test_tool_name", map[string]any{"ip": "1.2.3.4"}, func(s string) {})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Invalid tool name
	_, err = executor.ExecuteByToolName("missing_tool", map[string]any{"ip": "1.2.3.4"}, func(s string) {})
	if err == nil {
		t.Error("expected error for missing tool")
	}
}
