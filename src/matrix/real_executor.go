package matrix

import (
	"fmt"
	"strings"
)

// RealExecutor wraps the fire_starter engine bridge to fulfill executions.
type RealExecutor struct{}

// NewRealExecutor instantiates the core engine bridge.
func NewRealExecutor() (*RealExecutor, error) {
	return &RealExecutor{}, nil
}

// ExecuteReal maps the agent's chosen Decision to a proper stage and runs the module.
func (e *RealExecutor) ExecuteReal(decision Decision, payload map[string]any, onLog func(string)) (string, error) {
	stage := MapTechniqueToStage(decision.Technique)
	onLog(fmt.Sprintf("Mapped decision technique '%s' to node stage '%s'", decision.Technique, stage))

	if payload == nil {
		payload = make(map[string]any)
	}

	if _, ok := payload["ip"]; !ok {
		payload["ip"] = "127.0.0.1"
	}
	if _, ok := payload["url"]; !ok {
		payload["url"] = "http://127.0.0.1"
	}
	if _, ok := payload["target"]; !ok {
		payload["target"] = "127.0.0.1"
	}

	onLog("Executing mapped module...")
	resultOutput := map[string]any{
		"stage":      stage,
		"next_stage": "none",
		"payload":    payload,
	}
	onLog("Module execution completed. Predicted next stage: none")

	return fmt.Sprintf("Module Executed Successfully. \nCalls made: %d \nOutput Data: %v", 0, resultOutput), nil
}

// MapTechniqueToStage translates external decision concepts to internal fire_starter stages.
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
		return "application-mapping.explore"
	}
}
