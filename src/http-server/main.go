package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"blackwater/src/matrix"
	chlog "github.com/charmbracelet/log"
)

type ExecuteRequest struct {
	Identifier string         `json:"identifier"`
	ToolName   string         `json:"tool_name"`
	Payload    map[string]any `json:"payload"`
}

type StreamUpdate struct {
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Result  any    `json:"result,omitempty"`
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

func main() {
	logger := chlog.NewWithOptions(os.Stderr, chlog.Options{
		ReportTimestamp: true,
		TimeFormat:      time.RFC3339,
	})
	chlog.SetDefault(logger)

	decisionsFile := "src/matrix/decisions.json"
	if _, err := os.Stat(decisionsFile); os.IsNotExist(err) {
		decisionsFile = filepath.Join("..", "..", "src", "matrix", "decisions.json")
	}

	bytes, err := os.ReadFile(decisionsFile)
	if err != nil {
		chlog.Fatal("Error reading decisions.json", "error", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		chlog.Fatal("Error parsing JSON", "error", err)
	}

	executor, err := matrix.NewRealExecutor(data.Decisions)
	if err != nil {
		chlog.Fatal("Failed to initialize executor", "error", err)
	}

	toolDefs := executor.Tools()
	toolByName := make(map[string]matrix.ToolDefinition, len(toolDefs))
	for _, tool := range toolDefs {
		toolByName[tool.Name] = tool
	}

	http.HandleFunc("/tools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"tools": toolDefs}); err != nil {
			http.Error(w, "Failed to encode tools", http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		chlog.Info("Tool request received", "endpoint", "/execute", "identifier", req.Identifier, "tool_name", req.ToolName, "payload", req.Payload)

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			chlog.Error("Streaming not supported")
			return
		}

		enc := json.NewEncoder(w)
		sendUpdate := func(update StreamUpdate) {
			_ = enc.Encode(update)
			flusher.Flush()
			chlog.Info("Tool response sent", "endpoint", "/execute", "level", update.Level, "done", update.Done)
		}

		resultData, executionContext, executeErr := executeRequest(req, data.Decisions, toolByName, executor, func(msg string) {
			sendUpdate(StreamUpdate{Level: "debug", Message: msg})
		})
		if executeErr != nil {
			sendUpdate(StreamUpdate{Level: "error", Message: fmt.Sprintf("Execution error: %v", executeErr)})
		} else {
			sendUpdate(StreamUpdate{Level: "info", Message: "Execution finished."})
		}

		finalResponse := map[string]any{
			"result": resultData,
			"matrix": data.Decisions,
			"tools":  toolDefs,
		}
		for key, value := range executionContext {
			finalResponse[key] = value
		}

		sendUpdate(StreamUpdate{Done: true, Result: finalResponse})
	})

	http.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var rpcReq JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
			writeJSONRPCError(w, nil, -32700, "Parse error")
			return
		}

		if rpcReq.JSONRPC != "2.0" {
			writeJSONRPCError(w, rpcReq.ID, -32600, "Invalid Request")
			return
		}

		switch rpcReq.Method {
		case "initialize":
			protocolVersion := "2024-11-05"
			var params map[string]any
			if len(rpcReq.Params) > 0 && json.Unmarshal(rpcReq.Params, &params) == nil {
				if p, ok := params["protocolVersion"].(string); ok && p != "" {
					protocolVersion = p
				}
			}
			writeJSONRPCResult(w, rpcReq.ID, map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "fire_starter",
					"version": "0.1.0",
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			tools := make([]map[string]any, 0, len(toolDefs))
			for _, tool := range toolDefs {
				tools = append(tools, map[string]any{
					"name":        tool.Name,
					"description": tool.Description,
					"inputSchema": tool.InputSchema,
				})
			}
			writeJSONRPCResult(w, rpcReq.ID, map[string]any{"tools": tools})
		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
				writeJSONRPCError(w, rpcReq.ID, -32602, "Invalid params")
				return
			}
			if params.Name == "" {
				writeJSONRPCError(w, rpcReq.ID, -32602, "Invalid params")
				return
			}
			payload := params.Arguments
			if nested, ok := params.Arguments["payload"].(map[string]any); ok {
				payload = nested
			}
			if payload == nil {
				payload = map[string]any{}
			}
			chlog.Info("Tool request received", "endpoint", "/message", "method", "tools/call", "tool_name", params.Name, "payload", payload)
			resultData, execErr := executor.ExecuteByToolName(params.Name, payload, func(string) {})
			if execErr != nil {
				chlog.Error("Tool response sent", "endpoint", "/message", "method", "tools/call", "tool_name", params.Name, "error", execErr)
				writeJSONRPCResult(w, rpcReq.ID, map[string]any{
					"isError": true,
					"content": []map[string]any{{
						"type": "text",
						"text": execErr.Error(),
					}},
				})
				return
			}
			chlog.Info("Tool response sent", "endpoint", "/message", "method", "tools/call", "tool_name", params.Name)
			writeJSONRPCResult(w, rpcReq.ID, map[string]any{
				"content": []map[string]any{{
					"type": "text",
					"text": resultData,
				}},
			})
		default:
			writeJSONRPCError(w, rpcReq.ID, -32601, "Method not found")
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "fire_starter", "status": "ok"})
			return
		}
		if r.Method == http.MethodPost {
			r.URL.Path = "/message"
			http.DefaultServeMux.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	chlog.Info("Starting MCP HTTP Server", "addr", ":8888")
	chlog.Info("MCP endpoint", "url", "http://localhost:8888/message")
	chlog.Info("Tool list endpoint", "url", "http://localhost:8888/tools")
	if err := http.ListenAndServe(":8888", nil); err != nil {
		chlog.Fatal("HTTP server failed", "error", err)
	}
}

func executeRequest(req ExecuteRequest, decisions []matrix.Decision, toolByName map[string]matrix.ToolDefinition, executor *matrix.RealExecutor, onLog func(string)) (string, map[string]any, error) {
	switch {
	case req.ToolName != "":
		tool, ok := toolByName[req.ToolName]
		if !ok {
			return "", map[string]any{"error": "tool not found"}, fmt.Errorf("tool not found")
		}
		onLog(fmt.Sprintf("Starting execution for tool: %s", tool.Name))
		resultData, executeErr := executor.ExecuteByToolName(req.ToolName, req.Payload, onLog)
		return resultData, map[string]any{"tool": tool}, executeErr
	case req.Identifier != "":
		var chosenDecision *matrix.Decision
		for i := range decisions {
			if decisions[i].Identifier == req.Identifier {
				chosenDecision = &decisions[i]
				break
			}
		}
		if chosenDecision == nil {
			return "", map[string]any{"error": "decision not found"}, fmt.Errorf("decision not found")
		}
		onLog(fmt.Sprintf("Starting execution for technique: %s", chosenDecision.Technique))
		resultData, executeErr := executor.ExecuteByIdentifier(req.Identifier, req.Payload, onLog)
		return resultData, map[string]any{"decision": chosenDecision}, executeErr
	default:
		return "", map[string]any{"error": "identifier or tool_name is required"}, fmt.Errorf("identifier or tool_name is required")
	}
}

func writeJSONRPCResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	})
}
