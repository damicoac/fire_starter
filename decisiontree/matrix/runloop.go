package matrix

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type RunLoop struct {
	decisions []Decision
	agent     Agent
	executor  Executor
	history   []ExecutionResult
}

func NewRunLoop(decisions []Decision, agent Agent, executor Executor) *RunLoop {
	return &RunLoop{
		decisions: decisions,
		agent:     agent,
		executor:  executor,
		history:   make([]ExecutionResult, 0),
	}
}

// InteractiveStep simulates a single pass through the runloop prompting for User Review of top 3 options
func (r *RunLoop) InteractiveStep(reader *bufio.Reader) (bool, error) {
	fmt.Println("\n--- New Agent Proposal Cycle ---")

	// 1. Agent evaluates history and predicts Top 3 actions (MCP Simulation)
	proposals := r.agent.ProposeDecisions(r.history, r.decisions, 3)
	if len(proposals) == 0 {
		fmt.Println("No decisions available to propose.")
		return false, nil
	}

	// 2. Persent to user for review
	fmt.Println("Agent proposed the following actions for your review:")
	for i, p := range proposals {
		fmt.Printf("%d. [%s]\n   Use Case: %s\n", i+1, p.Technique, p.UseCase)
	}
	fmt.Println("0. Stop runloop")

	fmt.Print("\nSelect an action (0-3): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil || choice < 0 || choice > len(proposals) {
		fmt.Println("Invalid choice, cycle skipped.")
		return true, nil // user typed invalid stuff, gracefully continue loop
	}

	if choice == 0 {
		fmt.Println("User ended the runloop.")
		return false, nil
	}

	selected := proposals[choice-1]
	fmt.Printf("\nExecuting technique: %s\n", selected.Technique)

	// 3. User approved, so Execute Tool Action
	resultData, err := r.executor.Execute(selected)
	if err != nil {
		fmt.Printf("Execution failed: %v\n", err)
		return true, nil
	}

	fmt.Printf("Agent received result: %s\n", resultData)

	// 4. Send Context Loop back
	r.history = append(r.history, ExecutionResult{
		DecisionSelected: selected,
		ResultData:       resultData,
		Timestamp:        time.Now(),
	})

	return true, nil
}

// Run starts the interactive console
func (r *RunLoop) Run() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		shouldContinue, err := r.InteractiveStep(reader)
		if err != nil {
			return err
		}
		if !shouldContinue {
			break
		}
	}
	return nil
}
