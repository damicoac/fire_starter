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
	server := mcp.NewMCPServer(kg)

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

	if len(tools) == 0 {
		t.Fatalf("expected at least 1 tool registered on MCP server")
	}

	if tools[0].Name != "fire_starter_query_kg" {
		t.Errorf("expected tool 'fire_starter_query_kg', got %s", tools[0].Name)
	}

	// 2. Verify tools/call over JSON-RPC
	resRaw, err := client.CallTool(ctx, "fire_starter_query_kg", nil)
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(resRaw, &res); err != nil {
		t.Fatalf("failed to unmarshal tool result: %v", err)
	}

	if _, exists := res["target_url_count"]; !exists {
		t.Errorf("expected 'target_url_count' field in Knowledge Graph query response")
	}
}
