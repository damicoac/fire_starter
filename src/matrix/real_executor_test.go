package matrix

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	modules "fire_starter/src/modules/core"
)

func TestRealExecutor_OSCommandInjection(t *testing.T) {
	// Start a mock server
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		// Just return success for reflection detection if needed
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "uid=1000(test) gid=1000(test) groups=1000(test)")
	}))
	defer ts.Close()

	if ts.Client().Transport != nil {
		restoreTransport := modules.SetDefaultTransport(ts.Client().Transport)
		defer restoreTransport()
	}

	decision := Decision{
		Identifier: "10",
		Technique:  "os_command_injection",
	}
	executor, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}
	payload := map[string]any{
		"ip":        "127.0.0.1",
		"url":       ts.URL,
		"threads":   10,
		"threshold": 1,
	}

	output, err := executor.ExecuteByToolName(context.Background(), "decision_os_command_injection", payload, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, "os_command_injection_results") {
		t.Errorf("Output does not contain os_command_injection_results: %s", output)
	}

	if atomic.LoadInt32(&requestCount) == 0 {
		t.Error("Mock server did not receive any requests")
	}
}

func TestDecisionPhase(t *testing.T) {
	tests := []struct {
		phase    string
		expected Phase
	}{
		{"", PhaseReconnaissance},
		{"not-a-phase", PhaseReconnaissance},
		{string(PhaseReconnaissance), PhaseReconnaissance},
		{string(PhaseScanning), PhaseScanning},
		{string(PhaseVulnerabilityAnalysis), PhaseVulnerabilityAnalysis},
		{string(PhaseExploitation), PhaseExploitation},
		{string(PhasePostExploitation), PhasePostExploitation},
		{string(PhaseReporting), PhaseReporting},
	}

	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			got := decisionPhase(tt.phase)
			if got != string(tt.expected) {
				t.Errorf("decisionPhase(%q) = %q, want %q", tt.phase, got, tt.expected)
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

	decision := Decision{
		Identifier: "ssti",
		Technique:  "server_side_template_injection_ssti",
	}
	executor, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	payload := map[string]any{
		"ip":      "127.0.0.1",
		"url":     ts.URL,
		"threads": 10,
	}

	output, err := executor.ExecuteByToolName(context.Background(), "decision_server_side_template_injection_ssti", payload, func(string) {})
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

	decision := Decision{
		Identifier: "path_traversal",
		Technique:  "path_traversal_attack",
	}
	executor, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	payload := map[string]any{
		"ip":      "127.0.0.1",
		"url":     ts.URL,
		"threads": 10,
	}

	output, err := executor.ExecuteByToolName(context.Background(), "decision_path_traversal_attack", payload, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, "path_traversal_attack_results") {
		t.Errorf("Output does not contain path_traversal_attack_results: %s", output)
	}
}

func TestRealExecutor_TechniqueMatching(t *testing.T) {
	decision1 := Decision{
		Identifier: "1",
		Technique:  "json_hijacking",
	}
	decision2 := Decision{
		Identifier: "2",
		Technique:  "google_dorking",
	}
	executor, _ := NewRealExecutor([]Decision{decision1, decision2})

	output1, _ := executor.ExecuteByToolName(context.Background(), "decision_json_hijacking", map[string]any{"url": "http://127.0.0.1"}, func(string) {})
	if strings.Contains(output1, "JsonHijackingTest") {
		t.Errorf("Expected json_hijacking to NOT match json_hijacking_test, but it did.")
	}

	output2, _ := executor.ExecuteByToolName(context.Background(), "decision_google_dorking", map[string]any{"url": "http://127.0.0.1"}, func(string) {})
	if strings.Contains(output2, "unknown technique") {
		t.Errorf("Expected google_dorking to match its registered module, but it returned an unknown-technique error: %s", output2)
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
			resp, err := http.Get(oobURL)
			if err == nil {
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OOB simulated")
	}))
	defer ts.Close()

	if ts.Client().Transport != nil {
		restoreTransport := modules.SetDefaultTransport(ts.Client().Transport)
		defer restoreTransport()
	}

	decision := Decision{
		Identifier: "ssti_oob",
		Technique:  "server_side_template_injection_ssti",
	}
	executor, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	payload := map[string]any{
		"ip":      "127.0.0.1",
		"url":     ts.URL + "?q=test", // Providing a vector to avoid default 3 vectors
		"threads": 5,
	}

	output, err := executor.ExecuteByToolName(context.Background(), "decision_server_side_template_injection_ssti", payload, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(strings.ToLower(output), "oob") || !strings.Contains(strings.ToLower(output), "vulnerable") {
		t.Errorf("Output does not contain OOB vulnerability: %s", output)
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

	// Unknown technique now returns an error instead of silent success
	_, err := executor.ExecuteByToolName(context.Background(), "test_tool_name", map[string]any{"ip": "1.2.3.4"}, func(s string) {})
	if err == nil {
		t.Error("expected error for unknown technique")
	}

	// Missing target url/ip returns an error instead of defaulting to loopback
	_, err = executor.ExecuteByToolName(context.Background(), "test_tool_name", map[string]any{}, func(s string) {})
	if err == nil {
		t.Error("expected error for payload missing target url/ip")
	}

	// Invalid tool name
	_, err = executor.ExecuteByToolName(context.Background(), "missing_tool", map[string]any{"ip": "1.2.3.4"}, func(s string) {})
	if err == nil {
		t.Error("expected error for missing tool")
	}
}

// TestRealExecutor_ExecuteByToolName_StageFromPhase: the dispatched decision's
// declared phase flows into the result output's "stage" field — a
// non-reconnaissance technique must not be coerced to "reconnaissance".
func TestRealExecutor_ExecuteByToolName_StageFromPhase(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "no command output here")
	}))
	defer ts.Close()

	decision := Decision{
		Identifier: "10",
		Technique:  "os_command_injection",
		Phase:      string(PhaseExploitation),
	}
	executor, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}

	output, err := executor.ExecuteByToolName(context.Background(), "decision_os_command_injection", map[string]any{
		"ip":  "127.0.0.1",
		"url": ts.URL,
	}, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !strings.Contains(output, `"stage": "exploitation"`) {
		t.Errorf("Output does not carry the decision's exploitation stage: %s", output)
	}
	if strings.Contains(output, `"stage": "reconnaissance"`) {
		t.Errorf("Non-recon technique was coerced to the reconnaissance stage: %s", output)
	}
}

// TestRealExecutor_OOBPublicHostInjection: the configured OOB public host is
// injected into the payload as "oob_host" before factory lookup (and echoed in
// the result output); without a configured host no oob_host key is injected.
func TestRealExecutor_OOBPublicHostInjection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "no command output here")
	}))
	defer ts.Close()

	decision := Decision{
		Identifier: "10",
		Technique:  "os_command_injection",
	}

	withHost, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}
	withHost.SetOOBPublicHost("oob.example.com:9000")
	output, err := withHost.ExecuteByToolName(context.Background(), "decision_os_command_injection", map[string]any{
		"ip":  "127.0.0.1",
		"url": ts.URL,
	}, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !strings.Contains(output, `"oob_host": "oob.example.com:9000"`) {
		t.Errorf("expected injected oob_host in output, got: %s", output)
	}

	withoutHost, err := NewRealExecutor([]Decision{decision})
	if err != nil {
		t.Fatalf("Failed to create RealExecutor: %v", err)
	}
	output, err = withoutHost.ExecuteByToolName(context.Background(), "decision_os_command_injection", map[string]any{
		"ip":  "127.0.0.1",
		"url": ts.URL,
	}, func(string) {})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if strings.Contains(output, "oob_host") {
		t.Errorf("expected no injected oob_host without a configured host, got: %s", output)
	}
}
