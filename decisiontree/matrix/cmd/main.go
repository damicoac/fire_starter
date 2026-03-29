package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"blackwater/decisiontree/matrix"
)

func main() {
	// Look up one directory to read decisions.json from 'decisiontree/matrix/decisions.json'
	decisionsFile := filepath.Join("..", "decisions.json")

	bytes, err := os.ReadFile(decisionsFile)
	if err != nil {
		fmt.Printf("Error reading decisions.json (expected at %s): %v\n", decisionsFile, err)
		os.Exit(1)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	agent := matrix.NewMockAgent()
	executor := matrix.NewMockExecutor()

	loop := matrix.NewRunLoop(data.Decisions, agent, executor)

	fmt.Printf("Loaded %d possible decisions. Starting interactive MCP runloop simulation...\n", len(data.Decisions))
	
	if err := loop.Run(); err != nil {
		fmt.Printf("RunLoop encountered a fatal error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Simulation ended.")
}
