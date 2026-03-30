package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"blackwater/src/matrix"
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

func main() {
	decisionsFile := "src/matrix/decisions.json"
	if _, err := os.Stat(decisionsFile); os.IsNotExist(err) {
		decisionsFile = filepath.Join("..", "..", "src", "matrix", "decisions.json")
	}

	bytes, err := os.ReadFile(decisionsFile)
	if err != nil {
		log.Fatalf("Error reading decisions.json: %v", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	executor, err := matrix.NewRealExecutor(data.Decisions)
	if err != nil {
		log.Fatalf("Failed to initialize executor: %v", err)
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

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Println("Streaming not supported")
			return
		}

		enc := json.NewEncoder(w)
		sendUpdate := func(update StreamUpdate) {
			enc.Encode(update)
			flusher.Flush()
		}

		var resultData string
		var executeErr error
		var executionContext map[string]any

		switch {
		case req.ToolName != "":
			tool, ok := toolByName[req.ToolName]
			if !ok {
				sendUpdate(StreamUpdate{Level: "error", Message: "Tool not found"})
				sendUpdate(StreamUpdate{Done: true, Result: map[string]any{"error": "tool not found"}})
				return
			}
			sendUpdate(StreamUpdate{Level: "info", Message: fmt.Sprintf("Starting execution for tool: %s", tool.Name)})
			resultData, executeErr = executor.ExecuteByToolName(req.ToolName, req.Payload, func(msg string) {
				sendUpdate(StreamUpdate{Level: "debug", Message: msg})
			})
			executionContext = map[string]any{"tool": tool}
		case req.Identifier != "":
			var chosenDecision *matrix.Decision
			for i := range data.Decisions {
				if data.Decisions[i].Identifier == req.Identifier {
					chosenDecision = &data.Decisions[i]
					break
				}
			}
			if chosenDecision == nil {
				sendUpdate(StreamUpdate{Level: "error", Message: "Decision not found"})
				sendUpdate(StreamUpdate{Done: true, Result: map[string]any{"error": "decision not found"}})
				return
			}
			sendUpdate(StreamUpdate{Level: "info", Message: fmt.Sprintf("Starting execution for technique: %s", chosenDecision.Technique)})
			resultData, executeErr = executor.ExecuteByIdentifier(req.Identifier, req.Payload, func(msg string) {
				sendUpdate(StreamUpdate{Level: "debug", Message: msg})
			})
			executionContext = map[string]any{"decision": chosenDecision}
		default:
			sendUpdate(StreamUpdate{Level: "error", Message: "identifier or tool_name is required"})
			sendUpdate(StreamUpdate{Done: true, Result: map[string]any{"error": "identifier or tool_name is required"}})
			return
		}

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

	fmt.Println("Starting Streamable HTTP MCP Server on :8080")
	fmt.Println("To list tools run: curl http://localhost:8080/tools")
	fmt.Println("To execute run: curl -N -X POST http://localhost:8080/execute -d '{\"identifier\":\"0000\"}'")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
