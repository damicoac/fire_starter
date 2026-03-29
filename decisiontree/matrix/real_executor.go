package matrix

import (
	"context"
	"fmt"
	"strings"

	"blackwater/decisiontree"
	"github.com/charmbracelet/log"
)

// RealExecutor wraps the decisiontree.Tree engine to fulfill executions
type RealExecutor struct {
	tree *decisiontree.Tree
}

// NewRealExecutor instantiates the core engine with registered modules
func NewRealExecutor() (*RealExecutor, error) {
	logger := log.New()
	tree, err := decisiontree.NewTreeFromRegistry(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to init tree from registry: %w", err)
	}
	return &RealExecutor{tree: tree}, nil
}

// ExecuteReal maps the agent's chosen Decision to a proper tree Stage and runs the Node
func (e *RealExecutor) ExecuteReal(decision Decision, payload map[string]any, onLog func(string)) (string, error) {
	stage := MapTechniqueToStage(decision.Technique)
	onLog(fmt.Sprintf("Mapped decision technique '%s' to node stage '%s'", decision.Technique, stage))

	if payload == nil {
		payload = make(map[string]any)
	}

	// Supply default dummy data for common payload requirements to satisfy payload helpers
	if _, ok := payload["ip"]; !ok {
		payload["ip"] = "127.0.0.1"
	}
	if _, ok := payload["url"]; !ok {
		payload["url"] = "http://127.0.0.1"
	}
	if _, ok := payload["target"]; !ok {
		payload["target"] = "127.0.0.1"
	}

	input := decisiontree.ThirdPartyInput{
		Stage:   stage,
		Payload: payload,
	}

	onLog("Finding matching tool in registry...")
	tool, err := e.tree.SelectTool(input)
	if err != nil {
		return "", fmt.Errorf("failed to select tool for stage %s: %w", stage, err)
	}

	onLog(fmt.Sprintf("Executing module %s...", tool.Name))
	result, err := tool.Run(context.Background(), input)
	if err != nil {
		return "", fmt.Errorf("module execution failed: %w", err)
	}

	nextStage := "none"
	if ns, ok := result.Output["next_stage"].(string); ok {
		nextStage = ns
	}
	onLog(fmt.Sprintf("Module execution completed. Predicted next stage: %s", nextStage))

	return fmt.Sprintf("Module Executed Successfully. \nCalls made: %d \nOutput Data: %v", len(result.Calls), result.Output), nil
}

// MapTechniqueToStage translates external DECISION concepts to internal DECISIONTREE stages
func MapTechniqueToStage(technique string) string {
	t := strings.ToLower(technique)

	switch {
	case strings.Contains(t, "port_scanning"):
		return "api-testing.recon"
	case strings.Contains(t, "injection"):
		if strings.Contains(t, "sql") || strings.Contains(t, "nosql") || strings.Contains(t, "os_command") {
			return "api-testing.injection"
		}
		return "active-testing.injection"
	case strings.Contains(t, "fuzzing"):
		return "api-testing.fuzzing"
	case strings.Contains(t, "graphql"):
		return "api-testing.graphql"
	case strings.Contains(t, "rate_limit"):
		return "api-testing.rate-limit"
	case strings.Contains(t, "xss"):
		return "active-testing.xss"
	case strings.Contains(t, "business_logic") || strings.Contains(t, "race_condition"):
		return "active-testing.business-logic"
	case strings.Contains(t, "authorization") || strings.Contains(t, "idor"):
		return "active-testing.access-control"
	case strings.Contains(t, "google_dorking"):
		return "application-mapping.explore"
	case strings.Contains(t, "subdomain"):
		return "application-mapping.attack-surface"
	case strings.Contains(t, "crlf"):
		return "active-testing.input-probing"
	case strings.Contains(t, "error_message"):
		return "active-testing.error-handling"
	default:
		// Fallback to exploration stage
		return "application-mapping.explore"
	}
}
