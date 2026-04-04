package matrix

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blackwater/src/database"
)

type RunLoop struct {
	decisions      []Decision
	agent          Agent
	executor       Executor
	history        []ExecutionResult
	knowledgeGraph *KnowledgeGraph
	learner        database.ReinforcementLearner
	Autonomous     bool
}

func NewRunLoop(decisions []Decision, agent Agent, executor Executor, learner database.ReinforcementLearner) *RunLoop {
	return &RunLoop{
		decisions:      decisions,
		agent:          agent,
		executor:       executor,
		history:        make([]ExecutionResult, 0),
		knowledgeGraph: NewKnowledgeGraph(),
		learner:        learner,
		Autonomous:     false,
	}
}

// InteractiveStep simulates a single pass through the runloop
func (r *RunLoop) InteractiveStep(reader *bufio.Reader) (bool, error) {
	fmt.Println("\n--- New Agent Proposal Cycle ---")

	// 1. Agent evaluates history and predicts Top actions using RL and Context
	proposals := r.agent.ProposeDecisions(r.history, r.decisions, 3, r.knowledgeGraph)
	if len(proposals) == 0 {
		fmt.Println("No decisions available to propose.")
		return false, nil
	}

	var selected Decision
	if r.Autonomous {
		selected = proposals[0]
		fmt.Printf("Autonomous mode: automatically selected technique: %s\n", selected.Technique)
	} else {
		// 2. Present to user for review
		fmt.Println("Agent proposed the following actions for your review:")
		for i, p := range proposals {
			fmt.Printf("%d. [%s]\n   Use Case: %s\n", i+1, p.Technique, p.UseCase)
			if len(p.Payload) > 0 {
				fmt.Printf("   Payload: %v\n", p.Payload)
			}
		}
		fmt.Println("0. Stop runloop")
		fmt.Println("A. Switch to Autonomous Mode")

		fmt.Print("\nSelect an action (0-3 or A): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if strings.ToLower(input) == "a" {
			fmt.Println("Switching to Autonomous Mode...")
			r.Autonomous = true
			selected = proposals[0]
			fmt.Printf("Automatically executing first technique: %s\n", selected.Technique)
		} else {
			choice, err := strconv.Atoi(input)
			if err != nil || choice < 0 || choice > len(proposals) {
				fmt.Println("Invalid choice, cycle skipped.")
				return true, nil // user typed invalid stuff, gracefully continue loop
			}

			if choice == 0 {
				fmt.Println("User ended the runloop.")
				return false, nil
			}
			selected = proposals[choice-1]
		}
	}

	fmt.Printf("\nExecuting technique: %s\n", selected.Technique)

	// 3. User approved, so Execute Tool Action
	resultData, err := r.executor.Execute(selected)
	
	// Evaluate Success and Record Transition for RL
	reward := 1
	if err != nil || strings.Contains(strings.ToLower(resultData), "failed") || strings.Contains(strings.ToLower(resultData), "found 0") {
		reward = -1
	}

	if r.learner != nil {
		previousStage := "application-mapping.explore"
		if len(r.history) > 0 {
			previousStage = MapTechniqueToStage(r.history[len(r.history)-1].DecisionSelected.Technique)
		}
		currentStage := MapTechniqueToStage(selected.Technique)
		
		_ = r.learner.RecordTransition(context.Background(), previousStage, currentStage, reward)
	}

	if err != nil {
		fmt.Printf("Execution failed: %v\n", err)
		return true, nil
	}

	fmt.Printf("Agent received result: %s\n", resultData)

	// 4. Update Knowledge Graph with intelligent extraction
	r.extractIntelligence(resultData)

	// 5. Send Context Loop back
	r.history = append(r.history, ExecutionResult{
		DecisionSelected: selected,
		ResultData:       resultData,
		Timestamp:        time.Now(),
	})

	if r.Autonomous {
		time.Sleep(1 * time.Second) // Prevent console flooding
	}

	return true, nil
}

func (r *RunLoop) extractIntelligence(resultData string) {
	// Attempt to parse JSON to deeply inspect structured fields
	var parsed any
	if err := json.Unmarshal([]byte(resultData), &parsed); err == nil {
		signalKeys := map[string]struct{}{
			"status":   {},
			"state":    {},
			"detail":   {},
			"message":  {},
			"evidence": {},
		}
		var inspect func(any)
		inspect = func(v any) {
			switch val := v.(type) {
			case map[string]any:
				for k, child := range val {
					key := strings.ToLower(strings.TrimSpace(k))
					childText := strings.ToLower(strings.TrimSpace(fmt.Sprint(child)))
					if _, ok := signalKeys[key]; ok {
						if strings.Contains(childText, "vulnerab") || strings.Contains(childText, "exploit") || strings.Contains(childText, "confirmed") {
							r.knowledgeGraph.AddVulnerability("Vulnerability signal found: " + fmt.Sprint(child))
						}
					}
					inspect(child)
				}
			case []any:
				for _, child := range val {
					inspect(child)
				}
			}
		}
		inspect(parsed)
	}

	// Simple regex extraction for IPs and URLs
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	urlRegex := regexp.MustCompile(`https?://[^\s"']+`)

	ips := ipRegex.FindAllString(resultData, -1)
	for _, ip := range ips {
		r.knowledgeGraph.AddIP(ip)
	}

	urls := urlRegex.FindAllString(resultData, -1)
	for _, u := range urls {
		r.knowledgeGraph.AddURL(u)
	}
	
	if strings.Contains(strings.ToLower(resultData), "vulnerability") || strings.Contains(strings.ToLower(resultData), "exploited") {
		r.knowledgeGraph.AddVulnerability("Generic Vulnerability Detected")
	}
}

// Run starts the interactive or autonomous console
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
