package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"fire_starter/src/matrix"
)

type ToolHandler func(ctx context.Context, args map[string]interface{}) (interface{}, error)

type RegisteredTool struct {
	Descriptor ToolDescriptor
	Handler    ToolHandler
}

type MCPServer struct {
	kg    *matrix.KnowledgeGraph
	tools map[string]RegisteredTool
}

func NewMCPServer(kg *matrix.KnowledgeGraph) *MCPServer {
	server := &MCPServer{
		kg:    kg,
		tools: make(map[string]RegisteredTool),
	}
	server.registerBuiltinTools()
	return server
}

func (s *MCPServer) RegisterTool(desc ToolDescriptor, handler ToolHandler) {
	s.tools[desc.Name] = RegisteredTool{
		Descriptor: desc,
		Handler:    handler,
	}
}

func (s *MCPServer) registerBuiltinTools() {
	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_query_kg",
		Description: "Query Fire Starter Knowledge Graph entities",
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.kg == nil {
			return map[string]interface{}{"status": "empty"}, nil
		}
		snap := s.kg.Snapshot()
		return map[string]interface{}{
			"target_url_count": snap.DiscoveredURLCount,
			"target_ip_count":  snap.DiscoveredIPCount,
			"open_ports":        snap.OpenPorts,
		}, nil
	})
}

// ServeSTDIO reads JSON-RPC requests from reader and writes responses to writer
func (s *MCPServer) ServeSTDIO(reader io.Reader, writer io.Writer) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			respBytes, _ := json.Marshal(JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    -32700,
					Message: "Parse error",
				},
			})
			_, _ = writer.Write(append(respBytes, '\n'))
			continue
		}

		resp := s.handleRequest(context.Background(), req)
		respBytes, _ := json.Marshal(resp)
		_, _ = writer.Write(append(respBytes, '\n'))
	}
	return scanner.Err()
}

func (s *MCPServer) handleRequest(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "tools/list":
		var toolList []ToolDescriptor
		for _, t := range s.tools {
			toolList = append(toolList, t.Descriptor)
		}
		resRaw, _ := json.Marshal(map[string]interface{}{
			"tools": toolList,
		})
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  resRaw,
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: "Invalid params"},
			}
		}

		tool, exists := s.tools[params.Name]
		if !exists {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Tool %s not found", params.Name)},
			}
		}

		result, err := tool.Handler(ctx, params.Arguments)
		if err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32000, Message: err.Error()},
			}
		}

		resRaw, _ := json.Marshal(result)
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  resRaw,
		}

	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: -32601, Message: "Method not found"},
		}
	}
}
