package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"fire_starter/src/agent"
	"fire_starter/src/matrix"
	"fire_starter/src/mcp"
)

func TestDualMCPClientAndServer(t *testing.T) {
	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	kg := matrix.NewKnowledgeGraph()
	defer kg.Close()
	kg.AddURL("http://example.com/login", "")

	decisions := []matrix.Decision{
		{Identifier: "tool_test", Technique: "unknown_technique", UseCase: "testing"},
	}
	executor, _ := matrix.NewRealExecutor(decisions)

	server := mcp.NewMCPServer(kg, executor, nil)

	go func() {
		_ = server.ServeSTDIO(serverReader, serverWriter)
	}()

	client := NewMCPClient(clientReader, clientWriter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Verify tools/list over JSON-RPC
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("failed to list tools: %v", err)
	}

	if len(tools) < 7 {
		t.Fatalf("expected at least 7 tools registered on MCP server, got %d", len(tools))
	}

	toolMap := make(map[string]bool)
	for _, tDesc := range tools {
		toolMap[tDesc.Name] = true
	}

	expectedTools := []string{
		"fire_starter_query_kg",
		"fire_starter_get_sitemap",
		"fire_starter_get_vulnerabilities",
		"fire_starter_execute_module",
		"fire_starter_execute_tool",
		"fire_starter_list_modules",
		"fire_starter_list_tools",
		"fire_starter_get_target",
	}
	for _, exp := range expectedTools {
		if !toolMap[exp] {
			t.Errorf("expected tool %q to be registered", exp)
		}
	}

	// 2. Verify fire_starter_query_kg over JSON-RPC
	resRaw, err := client.CallTool(ctx, "fire_starter_query_kg", nil)
	if err != nil {
		t.Fatalf("failed to call fire_starter_query_kg: %v", err)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(resRaw, &res); err != nil {
		t.Fatalf("failed to unmarshal tool result: %v", err)
	}

	if _, exists := res["target_url_count"]; !exists {
		t.Errorf("expected 'target_url_count' field in Knowledge Graph query response")
	}

	// 3. Verify fire_starter_list_modules over JSON-RPC
	listResRaw, err := client.CallTool(ctx, "fire_starter_list_modules", nil)
	if err != nil {
		t.Fatalf("failed to call fire_starter_list_modules: %v", err)
	}
	var listRes map[string]interface{}
	if err := json.Unmarshal(listResRaw, &listRes); err != nil {
		t.Fatalf("failed to unmarshal list_modules result: %v", err)
	}
	if _, ok := listRes["modules"]; !ok {
		t.Errorf("expected 'modules' array in list_modules response")
	}

	// 4. Verify fire_starter_get_target over JSON-RPC
	targetResRaw, err := client.CallTool(ctx, "fire_starter_get_target", map[string]interface{}{"target": "example.com/login"})
	if err != nil {
		t.Fatalf("failed to call fire_starter_get_target: %v", err)
	}
	var targetRes map[string]interface{}
	if err := json.Unmarshal(targetResRaw, &targetRes); err != nil {
		t.Fatalf("failed to unmarshal get_target result: %v", err)
	}
	if targetRes["status"] != "found" {
		t.Errorf("expected target status 'found', got %v", targetRes["status"])
	}

	// 5. Verify fire_starter_get_sitemap over JSON-RPC
	sitemapResRaw, err := client.CallTool(ctx, "fire_starter_get_sitemap", map[string]interface{}{"target": "example.com/login"})
	if err != nil {
		t.Fatalf("failed to call fire_starter_get_sitemap: %v", err)
	}
	var sitemapRes map[string]interface{}
	if err := json.Unmarshal(sitemapResRaw, &sitemapRes); err != nil {
		t.Fatalf("failed to unmarshal get_sitemap result: %v", err)
	}
	if sitemapRes["status"] != "found" {
		t.Errorf("expected sitemap status 'found', got %v", sitemapRes["status"])
	}

	// 6. Verify fire_starter_get_vulnerabilities over JSON-RPC
	vulnsResRaw, err := client.CallTool(ctx, "fire_starter_get_vulnerabilities", nil)
	if err != nil {
		t.Fatalf("failed to call fire_starter_get_vulnerabilities: %v", err)
	}
	var vulnsRes map[string]interface{}
	if err := json.Unmarshal(vulnsResRaw, &vulnsRes); err != nil {
		t.Fatalf("failed to unmarshal get_vulnerabilities result: %v", err)
	}
	if _, ok := vulnsRes["vulnerabilities"]; !ok {
		t.Errorf("expected 'vulnerabilities' array in response")
	}

	// 6b. Verify fire_starter_get_vulnerabilities with target filter
	targetVulnsRaw, err := client.CallTool(ctx, "fire_starter_get_vulnerabilities", map[string]interface{}{"target": "example.com"})
	if err != nil {
		t.Fatalf("failed to call fire_starter_get_vulnerabilities with target: %v", err)
	}
	var targetVulnsRes map[string]interface{}
	if err := json.Unmarshal(targetVulnsRaw, &targetVulnsRes); err != nil {
		t.Fatalf("failed to unmarshal filtered vulns result: %v", err)
	}
	if _, ok := targetVulnsRes["vulnerabilities"]; !ok {
		t.Errorf("expected 'vulnerabilities' array in response")
	}
}

func TestMCPExecScopeGuard(t *testing.T) {
	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	kg := matrix.NewKnowledgeGraph()
	defer kg.Close()

	decisions := []matrix.Decision{
		{Identifier: "tool_scope", Technique: "unknown_technique", UseCase: "testing"},
	}
	executor, err := matrix.NewRealExecutor(decisions)
	if err != nil {
		t.Fatalf("failed to build executor: %v", err)
	}

	// Scope derived from an engagement config: only the configured target
	// (localhost) and its IPs are authorized.
	cfg := agent.Config{
		Target:      "localhost",
		IPWhitelist: []string{"127.0.0.1"},
	}
	server := mcp.NewMCPServer(kg, executor, agent.ConfigScopeAllow(cfg))

	go func() {
		_ = server.ServeSTDIO(serverReader, serverWriter)
	}()

	client := NewMCPClient(clientReader, clientWriter)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Execution against a non-whitelisted target must be rejected by the
	//    scope guard with a "target out of scope" JSON-RPC error.
	_, err = client.CallTool(ctx, "fire_starter_execute_module", map[string]interface{}{
		"module_name": "tool_scope",
		"payload":     map[string]interface{}{"url": "http://192.0.2.123/login"},
	})
	if err == nil {
		t.Fatal("expected JSON-RPC error for out-of-scope target, got nil")
	}
	if !strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("expected 'target out of scope' error, got %q", err.Error())
	}

	// 2. A payload with neither url nor ip is rejected as well (no silent
	//    fall back to module default targets).
	_, err = client.CallTool(ctx, "fire_starter_execute_tool", map[string]interface{}{
		"module_name": "tool_scope",
		"payload":     map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("expected 'target out of scope' error for empty payload, got %v", err)
	}

	// 2b. Bypass attempt: an in-scope url paired with an out-of-scope target
	//     key must still be rejected — the guard validates every host-ish
	//     key (url, ip, target), not just the first one present.
	_, err = client.CallTool(ctx, "fire_starter_execute_module", map[string]interface{}{
		"module_name": "tool_scope",
		"payload": map[string]interface{}{
			"url":    "http://127.0.0.1:59999/",
			"target": "http://198.51.100.7/",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("expected 'target out of scope' error for out-of-scope target key, got %v", err)
	}

	// 2c. Same bypass through the ip key.
	_, err = client.CallTool(ctx, "fire_starter_execute_tool", map[string]interface{}{
		"tool_name": "tool_scope",
		"payload": map[string]interface{}{
			"url": "http://127.0.0.1:59999/",
			"ip":  "198.51.100.7",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("expected 'target out of scope' error for out-of-scope ip key, got %v", err)
	}

	// 2d. Same bypass through a nested payload map (same key set the agent
	//     allowlist check covers).
	_, err = client.CallTool(ctx, "fire_starter_execute_module", map[string]interface{}{
		"module_name": "tool_scope",
		"payload": map[string]interface{}{
			"url": "http://127.0.0.1:59999/",
			"payload": map[string]interface{}{
				"target": "http://198.51.100.7/",
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("expected 'target out of scope' error for out-of-scope nested payload, got %v", err)
	}

	// 2e. A payload that addresses the in-scope target through the target
	//     key alone passes the guard (no false positive on that key).
	_, err = client.CallTool(ctx, "fire_starter_execute_module", map[string]interface{}{
		"module_name": "tool_scope",
		"payload": map[string]interface{}{
			"target": "http://127.0.0.1:59999/",
		},
	})
	if err != nil && strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("in-scope target key was rejected by the scope guard: %v", err)
	}

	// 3. A whitelisted target passes the guard. The module call itself may
	//    fail with its own (module-level) error — only the guard is asserted
	//    here: the response must not be the scope rejection.
	_, err = client.CallTool(ctx, "fire_starter_execute_module", map[string]interface{}{
		"module_name": "tool_scope",
		"payload":     map[string]interface{}{"url": "http://127.0.0.1:59999/"},
	})
	if err != nil && strings.Contains(err.Error(), "target out of scope") {
		t.Fatalf("whitelisted target was rejected by the scope guard: %v", err)
	}
}

func TestMCPDefaultScopeAllow(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"http://127.0.0.1:8080/", true},
		{"http://localhost/", true},
		{"http://192.0.2.10/", false},
		{"", false},
		{"http:///", false},
	}
	for _, tc := range cases {
		if got := mcp.DefaultScopeAllow(tc.target); got != tc.want {
			t.Errorf("defaultScopeAllow(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestMCPClient_ConnectionClosed(t *testing.T) {
	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	client := NewMCPClient(clientReader, clientWriter)

	// Close the reader simulating abrupt server termination
	_ = serverReader.Close()
	_ = serverWriter.Close()
	_ = clientReader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.CallMethod(ctx, "test_method", nil)
	if err == nil {
		t.Fatal("expected error on closed connection, got nil")
	}
}
