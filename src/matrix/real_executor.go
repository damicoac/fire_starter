package matrix

import (
	"context"
	"fmt"
	"strings"

	"blackwater/src/modules"
)

type RealExecutor struct {
	registry   *ToolRegistry
	toolByName map[string]ToolDefinition
}

func NewRealExecutor(decisions []Decision) (*RealExecutor, error) {
	registry := NewToolRegistry(decisions)
	toolByName := make(map[string]ToolDefinition, len(decisions))
	for _, tool := range registry.ListTools() {
		toolByName[tool.Name] = tool
	}
	return &RealExecutor{registry: registry, toolByName: toolByName}, nil
}

func (e *RealExecutor) Tools() []ToolDefinition {
	return e.registry.ListTools()
}

func (e *RealExecutor) Execute(decision Decision) (string, error) {
	return e.executeDecision(decision, map[string]any{}, func(string) {})
}

func (e *RealExecutor) ExecuteByIdentifier(identifier string, payload map[string]any, onLog func(string)) (string, error) {
	tool, ok := e.registry.ToolForIdentifier(identifier)
	if !ok {
		return "", fmt.Errorf("tool for identifier %s not found", identifier)
	}
	decision := Decision{Identifier: tool.Identifier, Technique: tool.Technique}
	return e.executeDecision(decision, payload, onLog)
}

func (e *RealExecutor) ExecuteByToolName(toolName string, payload map[string]any, onLog func(string)) (string, error) {
	tool, ok := e.toolByName[toolName]
	if !ok {
		return "", fmt.Errorf("tool %s not found", toolName)
	}
	decision := Decision{Identifier: tool.Identifier, Technique: tool.Technique}
	return e.executeDecision(decision, payload, onLog)
}

func (e *RealExecutor) ExecuteReal(decision Decision, payload map[string]any, onLog func(string)) (string, error) {
	return e.executeDecision(decision, payload, onLog)
}

func (e *RealExecutor) executeDecision(decision Decision, payload map[string]any, onLog func(string)) (string, error) {
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
		"decision_identifier": decision.Identifier,
		"technique":           decision.Technique,
		"stage":               stage,
		"next_stage":          "none",
		"payload":             payload,
	}

	// Execute real port scan for port_scanning technique
	if strings.Contains(strings.ToLower(decision.Technique), "port_scanning") {
		ip := payload["ip"].(string)
		onLog(fmt.Sprintf("Starting port scan on target: %s", ip))

		scanner := modules.NewPortScanner(ip, nil)
		scanner.SetThreads(50)

		results, err := scanner.ScanCommonPorts(context.Background())
		if err != nil {
			return fmt.Sprintf("Port scan failed: %v", err), err
		}

		onLog(fmt.Sprintf("Port scan completed. Found %d open ports", len(results)))

		// Build results map for output
		openPorts := make([]int, 0)
		for _, r := range results {
			if r.State == "open" {
				openPorts = append(openPorts, r.Port)
			}
		}
		resultOutput["open_ports"] = openPorts
		resultOutput["scan_results"] = results
	}

	// Execute subdomain enumeration for subdomain_enumeration technique
	if strings.Contains(strings.ToLower(decision.Technique), "subdomain_enumeration") {
		domain := payload["url"].(string)
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		parts := strings.Split(domain, "/")
		domain = parts[0]

		onLog(fmt.Sprintf("Starting subdomain enumeration on: %s", domain))

		enumerator := modules.NewSubdomainEnumerator(domain)

		results, err := enumerator.EnumerateWithPorts(context.Background())
		if err != nil {
			return fmt.Sprintf("Subdomain enumeration failed: %v", err), err
		}

		onLog(fmt.Sprintf("Subdomain enumeration completed. Found %d subdomains", len(results)))

		resultOutput["subdomain_results"] = results
	}

	onLog("Module execution completed. Predicted next stage: none")

	return fmt.Sprintf("Module Executed Successfully. \nCalls made: %d \nOutput Data: %v", 1, resultOutput), nil
}

func MapTechniqueToStage(technique string) string {
	t := strings.ToLower(technique)

	switch {
	case strings.Contains(t, "port_scanning"):
		return "api-testing.recon"
	case strings.Contains(t, "sql_injection") || strings.Contains(t, "nosql_injection") || strings.Contains(t, "os_command_injection") || strings.Contains(t, "ldap_injection") || strings.Contains(t, "xpath_injection"):
		return "api-testing.injection"
	case strings.Contains(t, "cross_site_scripting") || strings.Contains(t, "dom_based_xss"):
		return "active-testing.xss"
	case strings.Contains(t, "idor") || strings.Contains(t, "broken_object_level_authorization") || strings.Contains(t, "broken_function_level_authorization") || strings.Contains(t, "http_verb_tampering"):
		return "active-testing.access-control"
	case strings.Contains(t, "replacive_fuzzing") || strings.Contains(t, "buffer_overflow") || strings.Contains(t, "password_spraying") || strings.Contains(t, "token_entropy"):
		return "api-testing.fuzzing"
	case strings.Contains(t, "google_dorking"):
		return "application-mapping.explore"
	case strings.Contains(t, "graphql"):
		return "api-testing.graphql"
	case strings.Contains(t, "subdomain_enumeration") || strings.Contains(t, "subdomain_takeover"):
		return "application-mapping.attack-surface"
	case strings.Contains(t, "ssrf") || strings.Contains(t, "xml_external_entity") || strings.Contains(t, "server_side_template_injection") || strings.Contains(t, "insecure_deserialization") || strings.Contains(t, "ssi_injection"):
		return "active-testing.injection"
	case strings.Contains(t, "csrf") || strings.Contains(t, "session_fixation") || strings.Contains(t, "jwt") || strings.Contains(t, "saml") || strings.Contains(t, "cors_misconfiguration"):
		return "active-testing.configuration-checks"
	case strings.Contains(t, "race_condition") || strings.Contains(t, "mass_assignment"):
		return "active-testing.business-logic"
	case strings.Contains(t, "cloud_storage_fuzzing"):
		return "application-mapping.explore"
	case strings.Contains(t, "http_parameter_pollution") || strings.Contains(t, "crlf_injection") || strings.Contains(t, "path_traversal") || strings.Contains(t, "json_hijacking"):
		return "active-testing.input-probing"
	case strings.Contains(t, "error_message"):
		return "active-testing.error-handling"
	case strings.Contains(t, "rate_limit"):
		return "api-testing.rate-limit"
	default:
		return "application-mapping.explore"
	}
}
