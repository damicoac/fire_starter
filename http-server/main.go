package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"blackwater/decisiontree/matrix"
)

type ExecuteRequest struct {
	Identifier string         `json:"identifier"`
	Payload    map[string]any `json:"payload"`
}

type StreamUpdate struct {
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Result  any    `json:"result,omitempty"`
}

func main() {
	decisionsFile := "decisiontree/matrix/decisions.json"
	// Also fallback to looking up directories if run from nested places
	if _, err := os.Stat(decisionsFile); os.IsNotExist(err) {
		decisionsFile = filepath.Join("..", "..", "decisiontree", "matrix", "decisions.json")
	}

	bytes, err := os.ReadFile(decisionsFile)
	if err != nil {
		log.Fatalf("Error reading decisions.json: %v", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	executor, err := matrix.NewRealExecutor()
	if err != nil {
		log.Fatalf("Failed to initialize executor: %v", err)
	}

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

		var chosenDecision *matrix.Decision
		for i := range data.Decisions {
			if data.Decisions[i].Identifier == req.Identifier {
				chosenDecision = &data.Decisions[i]
				break
			}
		}

		if chosenDecision == nil {
			http.Error(w, "Decision not found", http.StatusNotFound)
			return
		}

		// Standard streamable json HTTP headers
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

		sendUpdate(StreamUpdate{Level: "info", Message: fmt.Sprintf("Starting execution for technique: %s", chosenDecision.Technique)})

		resultData, executeErr := executor.ExecuteReal(*chosenDecision, req.Payload, func(msg string) {
			sendUpdate(StreamUpdate{Level: "debug", Message: msg})
		})

		if executeErr != nil {
			sendUpdate(StreamUpdate{Level: "error", Message: fmt.Sprintf("Execution error: %v", executeErr)})
		} else {
			sendUpdate(StreamUpdate{Level: "info", Message: "Execution finished."})
		}

		// Bundle the results with the overall decision matrix
		finalResponse := map[string]any{
			"result": resultData,
			"matrix": data.Decisions,
		}

		sendUpdate(StreamUpdate{Done: true, Result: finalResponse})
	})

	fmt.Println("Starting Streamable HTTP MCP Server on :8080")
	fmt.Println("To execute a decision run: curl -N -X POST http://localhost:8080/execute -d '{\"identifier\":\"0000\"}'")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
