package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	modules "fire_starter/src/modules/core"
)

type RealExecutor struct {
	registry   *ToolRegistry
	toolByName map[string]ToolDefinition
}

func payloadString(payload map[string]any, key, fallback string) string {
	v, ok := payload[key]
	if !ok || v == nil {
		return fallback
	}
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return fallback
		}
		return s
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" {
		return fallback
	}
	return s
}

func payloadInt(payload map[string]any, key string, fallback int) int {
	v, ok := payload[key]
	if !ok || v == nil {
		return fallback
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
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
	payload := decision.Payload
	if payload == nil {
		payload = make(map[string]any)
	}
	return e.executeDecision(decision, payload, func(string) {})
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

	ipStr := payloadString(payload, "ip", "")
	urlStr := payloadString(payload, "url", "")
	if urlStr != "" {
		urlStr = modules.EnsureHTTPPrefix(urlStr)
		payload["url"] = urlStr
	}
	cookiesStr := payloadString(payload, "cookies", "")

	if ipStr == "" && urlStr == "" {
		return "", fmt.Errorf("target IP address or URL is required")
	}

	// Cross-populate
	if urlStr == "" && ipStr != "" {
		payload["url"] = modules.EnsureHTTPPrefix(ipStr)
	}
	if ipStr == "" && urlStr != "" {
		if parsedIP := modules.ExtractHostname(urlStr); parsedIP != "" {
			payload["ip"] = parsedIP
		}
	}

	onLog("Executing mapped module...")
	resultOutput := map[string]any{
		"decision_identifier": decision.Identifier,
		"technique":           decision.Technique,
		"stage":               stage,
		"next_stage":          "none",
		"payload":             payload,
	}

	// Helper to inject cookies if the module supports it
	injectCookies := func(module any) {
		if cookiesStr != "" {
			if baseModule, ok := module.(interface{ SetCookies(string) }); ok {
				baseModule.SetCookies(cookiesStr)
			} else if hasBaseModule, ok := module.(interface{ GetBaseModule() *modules.BaseModule }); ok {
				hasBaseModule.GetBaseModule().Cookies = cookiesStr
			}
		}
	}

	technique := strings.ToLower(strings.TrimSpace(decision.Technique))

	factory, ok := modules.GetModuleFactory(technique)
	if !ok {
		onLog("No matching technique found for execution.")
	} else {
		module, err := factory(payload, onLog)
		if err != nil {
			return "", fmt.Errorf("failed to create module %s: %v", technique, err)
		}

		injectCookies(module.GetUnderlying())
		
		results, err := module.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("%s failed: %v", technique, err), err
		}
		resultOutput[technique + "_results"] = results

		if hasBaseModule, ok := module.GetUnderlying().(interface{ GetBaseModule() *modules.BaseModule }); ok {
			base := hasBaseModule.GetBaseModule()
			if base != nil {
				base.PocMu.Lock()
				if len(base.PoCs) > 0 {
					resultOutput["reproduction_steps"] = base.PoCs
				}
				base.PocMu.Unlock()
			}
		}
	}

	onLog("Module execution completed. Predicted next stage: none")

	jsonData, err := json.MarshalIndent(resultOutput, "", "  ")
	if err != nil {
		return fmt.Sprintf("Module Executed Successfully. \nCalls made: %d \nOutput Data: %v", 1, resultOutput), nil
	}

	return string(jsonData), nil
}

func MapTechniqueToStage(technique string) string {
	t := strings.ToLower(technique)

	switch {
	case strings.Contains(t, "google_dorking") || strings.Contains(t, "subdomain_enumeration") || strings.Contains(t, "subdomain_takeover"):
		return string(PhaseReconnaissance)
	case strings.Contains(t, "port_scanning") || strings.Contains(t, "error_message"):
		return string(PhaseScanning)
	case strings.Contains(t, "component_version_analyzer") || strings.Contains(t, "idor") || strings.Contains(t, "broken_object_level_authorization") || strings.Contains(t, "broken_function_level_authorization") || strings.Contains(t, "ssrf") || strings.Contains(t, "xml_external_entity") || strings.Contains(t, "server_side_template_injection") || strings.Contains(t, "insecure_deserialization") || strings.Contains(t, "ssi_injection") || strings.Contains(t, "http_verb_tampering") || strings.Contains(t, "security_headers") || strings.Contains(t, "websocket_vulnerability"):
		return string(PhaseVulnerabilityAnalysis)
	case strings.Contains(t, "sql_injection") || strings.Contains(t, "nosql_injection") || strings.Contains(t, "os_command_injection") || strings.Contains(t, "ldap_injection") || strings.Contains(t, "xpath_injection") || strings.Contains(t, "cross_site_scripting") || strings.Contains(t, "dom_based_xss") || strings.Contains(t, "csrf") || strings.Contains(t, "session_fixation") || strings.Contains(t, "jwt") || strings.Contains(t, "saml") || strings.Contains(t, "cors_misconfiguration") || strings.Contains(t, "race_condition") || strings.Contains(t, "mass_assignment") || strings.Contains(t, "http_parameter_pollution") || strings.Contains(t, "crlf_injection") || strings.Contains(t, "path_traversal") || strings.Contains(t, "json_hijacking") || strings.Contains(t, "unrestricted_file_upload") || strings.Contains(t, "oauth_misconfiguration") || strings.Contains(t, "mfa_bypass") || strings.Contains(t, "open_redirect") || strings.Contains(t, "http_request_smuggling") || strings.Contains(t, "business_logic_bypass") || strings.Contains(t, "graphql_advanced"):
		return string(PhaseExploitation)
	case strings.Contains(t, "rate_limit") || strings.Contains(t, "threat_monitoring"):
		return string(PhaseVulnerabilityAnalysis)
	case strings.Contains(t, "local_privilege_escalation") || strings.Contains(t, "ssh_pivot"):
		return string(PhasePostExploitation)
	default:
		return string(PhaseReconnaissance)
	}
}
