package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"fire_starter/src/matrix"
)

type ToolHandler func(ctx context.Context, args map[string]interface{}) (interface{}, error)

type RegisteredTool struct {
	Descriptor ToolDescriptor
	Handler    ToolHandler
}

type MCPServer struct {
	kg       *matrix.KnowledgeGraph
	executor *matrix.RealExecutor
	tools    map[string]RegisteredTool
}

func NewMCPServer(kg *matrix.KnowledgeGraph, executor *matrix.RealExecutor) *MCPServer {
	server := &MCPServer{
		kg:       kg,
		executor: executor,
		tools:    make(map[string]RegisteredTool),
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
	// 1. fire_starter_query_kg
	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_query_kg",
		Description: "Query Fire Starter Knowledge Graph entities, tokens, credentials, and summary metrics",
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.kg == nil {
			return map[string]interface{}{"status": "empty"}, nil
		}
		snap := s.kg.Snapshot()
		return map[string]interface{}{
			"target_url_count": snap.DiscoveredURLCount,
			"target_ip_count":  snap.DiscoveredIPCount,
			"open_ports":       snap.OpenPorts,
			"token_count":      snap.HarvestedTokenCount,
			"vuln_count":       snap.VulnerabilityCount,
			"targets":          s.kg.GetTargetValues(),
			"credentials":      s.kg.GetCredentials(),
		}, nil
	})

	// 2. fire_starter_get_sitemap
	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_get_sitemap",
		Description: "Fetch the hierarchical attack surface SiteMap tree for a target",
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.kg == nil {
			return nil, fmt.Errorf("knowledge graph not configured")
		}
		targetValue, _ := args["target"].(string)
		if targetValue == "" {
			return nil, fmt.Errorf("target argument is required")
		}
		target, ok := s.kg.GetTarget(targetValue)
		if !ok || target.SiteMap == nil {
			return map[string]interface{}{"status": "not_found"}, nil
		}
		return map[string]interface{}{
			"status":     "found",
			"target":     target.Value,
			"node_count": target.SiteMap.NodeCount(),
			"site_map":   target.SiteMap.Clone(),
		}, nil
	})

	// 3. fire_starter_get_vulnerabilities
	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_get_vulnerabilities",
		Description: "Query confirmed and candidate vulnerability findings from assessment records",
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		vulns, err := matrix.GetVulnerabilities()
		if err != nil {
			// When database is uninitialized, fall back to target vulnerabilities from Knowledge Graph
			if s.kg != nil {
				targetFilter, _ := args["target"].(string)
				var kgVulns []string
				if targetFilter != "" {
					if t, ok := s.kg.GetTarget(targetFilter); ok {
						kgVulns = append(kgVulns, t.Vulnerabilities...)
					}
				} else {
					for _, t := range s.kg.GetTargetsSnapshot() {
						kgVulns = append(kgVulns, t.Vulnerabilities...)
					}
				}
				return map[string]interface{}{"vulnerabilities": kgVulns}, nil
			}
			return map[string]interface{}{"vulnerabilities": []interface{}{}}, nil
		}
		targetFilter, _ := args["target"].(string)
		if targetFilter != "" {
			targetFilter = matrix.NormalizeURL(targetFilter)
			filtered := make([]matrix.VulnInfo, 0)
			for _, v := range vulns {
				if matrix.NormalizeURL(v.TargetDomain) == targetFilter {
					filtered = append(filtered, v)
				}
			}
			return map[string]interface{}{"vulnerabilities": filtered}, nil
		}
		return map[string]interface{}{"vulnerabilities": vulns}, nil
	})

	// 4. fire_starter_execute_module and fire_starter_execute_tool
	execHandler := func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.executor == nil {
			return nil, fmt.Errorf("executor not configured on MCP server")
		}
		moduleName, _ := args["module_name"].(string)
		if moduleName == "" {
			moduleName, _ = args["tool_name"].(string)
		}
		if moduleName == "" {
			return nil, fmt.Errorf("module_name or tool_name argument is required")
		}
		payload, _ := args["payload"].(map[string]interface{})
		if payload == nil {
			payload = make(map[string]interface{})
		}
		var logs []string
		result, err := s.executor.ExecuteByToolName(ctx, moduleName, payload, func(msg string) {
			logs = append(logs, msg)
		})
		if err != nil {
			return map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
				"logs":   logs,
			}, nil
		}

		target, _ := payload["url"].(string)
		if target == "" {
			target, _ = payload["ip"].(string)
		}
		if s.kg != nil && target != "" {
			_, _, _ = s.kg.ExtractIntelligence(ctx, nil, moduleName, target, payload, result)
		}

		return map[string]interface{}{
			"status": "success",
			"result": result,
			"logs":   logs,
		}, nil
	}

	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_execute_module",
		Description: "Execute any registered security module technique directly against a target with payload parameters",
	}, execHandler)

	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_execute_tool",
		Description: "Execute a specific Fire Starter offensive security tool against a target (alias for fire_starter_execute_module)",
	}, execHandler)

	// 5. fire_starter_list_modules and fire_starter_list_tools
	listHandler := func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.executor == nil {
			return map[string]interface{}{"modules": []interface{}{}, "tools": []interface{}{}}, nil
		}
		tools := s.executor.Tools()
		list := make([]map[string]interface{}, 0, len(tools))
		for _, t := range tools {
			list = append(list, map[string]interface{}{
				"name":        t.Name,
				"description": t.Description,
				"technique":   t.Technique,
			})
		}
		return map[string]interface{}{"modules": list, "tools": list}, nil
	}

	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_list_modules",
		Description: "List all available assessment modules and descriptions",
	}, listHandler)

	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_list_tools",
		Description: "List available automated offensive security tools and techniques (alias for fire_starter_list_modules)",
	}, listHandler)

	// 6. fire_starter_get_target
	s.RegisterTool(ToolDescriptor{
		Name:        "fire_starter_get_target",
		Description: "Retrieve detailed target intelligence including vulnerabilities, open ports, and sitemap",
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		if s.kg == nil {
			return nil, fmt.Errorf("knowledge graph not configured")
		}
		targetValue, _ := args["target"].(string)
		if targetValue == "" {
			return nil, fmt.Errorf("target argument is required")
		}
		target, ok := s.kg.GetTarget(targetValue)
		if !ok {
			return map[string]interface{}{"status": "not_found"}, nil
		}
		var nodeCount int
		if target.SiteMap != nil {
			nodeCount = target.SiteMap.NodeCount()
		}
		return map[string]interface{}{
			"status":          "found",
			"value":           target.Value,
			"type":            target.Type,
			"score":           target.Score,
			"current_phase":   target.CurrentPhase,
			"open_ports":      target.OpenPorts,
			"tokens":          target.Tokens,
			"vulnerabilities": target.Vulnerabilities,
			"sitemap_nodes":   nodeCount,
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
		sort.Slice(toolList, func(i, j int) bool {
			return toolList[i].Name < toolList[j].Name
		})
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
