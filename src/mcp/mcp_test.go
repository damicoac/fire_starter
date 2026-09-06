package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

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

	server := mcp.NewMCPServer(kg, executor)

	go func() {
		_ = server.ServeSTDIO(serverReader, serverWriter)
	}()

	client := mcp.NewMCPClient(clientReader, clientWriter)

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
}
