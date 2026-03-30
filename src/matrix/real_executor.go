package matrix

import (
	"context"
	"fmt"
	"strings"
	"time"

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

	if strings.Contains(strings.ToLower(decision.Technique), "google_dorking_for_apis") {
		target, _ := payload["target"].(string)
		onLog(fmt.Sprintf("Generating Google dork API queries for: %s", target))

		dorker := modules.NewGoogleDorkingForAPIs(target)
		results := dorker.Generate()

		onLog(fmt.Sprintf("Google dork API query generation completed. Generated %d queries", len(results)))
		resultOutput["google_dorking_for_apis_results"] = results
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

		enumCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		results, err := enumerator.EnumerateWithPorts(enumCtx)
		if err != nil {
			return fmt.Sprintf("Subdomain enumeration failed: %v", err), err
		}

		onLog(fmt.Sprintf("Subdomain enumeration completed. Found %d subdomains", len(results)))

		resultOutput["subdomain_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "http_parameter_pollution_hpp") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting HttpParameterPollutionHpp on: %s", target))

		tester := modules.NewHttpParameterPollutionHpp(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("HttpParameterPollutionHpp failed: %v", err), err
		}

		onLog(fmt.Sprintf("HttpParameterPollutionHpp completed. Found %d results", len(results)))
		resultOutput["http_parameter_pollution_hpp_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "cors_misconfiguration_analysis") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting CorsMisconfigurationAnalysis on: %s", target))

		tester := modules.NewCorsMisconfigurationAnalysis(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("CorsMisconfigurationAnalysis failed: %v", err), err
		}

		onLog(fmt.Sprintf("CorsMisconfigurationAnalysis completed. Found %d results", len(results)))
		resultOutput["cors_misconfiguration_analysis_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "google_dorking") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting GoogleDorking on: %s", target))

		tester := modules.NewGoogleDorking(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("GoogleDorking failed: %v", err), err
		}

		onLog(fmt.Sprintf("GoogleDorking completed. Found %d results", len(results)))
		resultOutput["google_dorking_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "x_m_l_external_entity_injection_xxe") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting XMLExternalEntityInjectionXxe on: %s", target))

		tester := modules.NewXMLExternalEntityInjectionXxe(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("XMLExternalEntityInjectionXxe failed: %v", err), err
		}

		onLog(fmt.Sprintf("XMLExternalEntityInjectionXxe completed. Found %d results", len(results)))
		resultOutput["x_m_l_external_entity_injection_xxe_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "j_w_t_security_audit") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting JWTSecurityAudit on: %s", target))

		tester := modules.NewJWTSecurityAudit(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("JWTSecurityAudit failed: %v", err), err
		}

		onLog(fmt.Sprintf("JWTSecurityAudit completed. Found %d results", len(results)))
		resultOutput["j_w_t_security_audit_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "http_verb_tampering") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting HttpVerbTampering on: %s", target))

		tester := modules.NewHttpVerbTampering(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("HttpVerbTampering failed: %v", err), err
		}

		onLog(fmt.Sprintf("HttpVerbTampering completed. Found %d results", len(results)))
		resultOutput["http_verb_tampering_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "rate_limit_probing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting RateLimitProbing on: %s", target))

		tester := modules.NewRateLimitProbing(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("RateLimitProbing failed: %v", err), err
		}

		onLog(fmt.Sprintf("RateLimitProbing completed. Found %d results", len(results)))
		resultOutput["rate_limit_probing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "nosql_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting NosqlInjectionTesting on: %s", target))

		tester := modules.NewNosqlInjectionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("NosqlInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("NosqlInjectionTesting completed. Found %d results", len(results)))
		resultOutput["nosql_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "xpath_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting XpathInjectionTesting on: %s", target))

		tester := modules.NewXpathInjectionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("XpathInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("XpathInjectionTesting completed. Found %d results", len(results)))
		resultOutput["xpath_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "server_side_template_injection_ssti") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting ServerSideTemplateInjectionSsti on: %s", target))

		tester := modules.NewServerSideTemplateInjectionSsti(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("ServerSideTemplateInjectionSsti failed: %v", err), err
		}

		onLog(fmt.Sprintf("ServerSideTemplateInjectionSsti completed. Found %d results", len(results)))
		resultOutput["server_side_template_injection_ssti_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "crlf_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting CrlfInjectionTesting on: %s", target))

		tester := modules.NewCrlfInjectionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("CrlfInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("CrlfInjectionTesting completed. Found %d results", len(results)))
		resultOutput["crlf_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "insecure_deserialization_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting InsecureDeserializationTesting on: %s", target))

		tester := modules.NewInsecureDeserializationTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("InsecureDeserializationTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("InsecureDeserializationTesting completed. Found %d results", len(results)))
		resultOutput["insecure_deserialization_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "buffer_overflow_probing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting BufferOverflowProbing on: %s", target))

		tester := modules.NewBufferOverflowProbing(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("BufferOverflowProbing failed: %v", err), err
		}

		onLog(fmt.Sprintf("BufferOverflowProbing completed. Found %d results", len(results)))
		resultOutput["buffer_overflow_probing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "race_condition_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting RaceConditionTesting on: %s", target))

		tester := modules.NewRaceConditionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("RaceConditionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("RaceConditionTesting completed. Found %d results", len(results)))
		resultOutput["race_condition_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "path_traversal_attack") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting PathTraversalAttack on: %s", target))

		tester := modules.NewPathTraversalAttack(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("PathTraversalAttack failed: %v", err), err
		}

		onLog(fmt.Sprintf("PathTraversalAttack completed. Found %d results", len(results)))
		resultOutput["path_traversal_attack_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "graphql_introspection") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting GraphqlIntrospection on: %s", target))

		tester := modules.NewGraphqlIntrospection(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("GraphqlIntrospection failed: %v", err), err
		}

		onLog(fmt.Sprintf("GraphqlIntrospection completed. Found %d results", len(results)))
		resultOutput["graphql_introspection_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "error_message_analysis") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting ErrorMessageAnalysis on: %s", target))

		tester := modules.NewErrorMessageAnalysis(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("ErrorMessageAnalysis failed: %v", err), err
		}

		onLog(fmt.Sprintf("ErrorMessageAnalysis completed. Found %d results", len(results)))
		resultOutput["error_message_analysis_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "cross_site_scripting_injection") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting CrossSiteScriptingInjection on: %s", target))

		tester := modules.NewCrossSiteScriptingInjection(target)
		if cookies, ok := payload["cookies"].(string); ok {
			tester.SetCookies(cookies)
		}
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("CrossSiteScriptingInjection failed: %v", err), err
		}

		onLog(fmt.Sprintf("CrossSiteScriptingInjection completed. Found %d results", len(results)))
		resultOutput["cross_site_scripting_injection_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "session_fixation_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SessionFixationTesting on: %s", target))

		tester := modules.NewSessionFixationTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SessionFixationTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("SessionFixationTesting completed. Found %d results", len(results)))
		resultOutput["session_fixation_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "cloud_storage_fuzzing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting CloudStorageFuzzing on: %s", target))

		tester := modules.NewCloudStorageFuzzing(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("CloudStorageFuzzing failed: %v", err), err
		}

		onLog(fmt.Sprintf("CloudStorageFuzzing completed. Found %d results", len(results)))
		resultOutput["cloud_storage_fuzzing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "subdomain_enumeration") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SubdomainEnumeration on: %s", target))

		tester := modules.NewSubdomainEnumeration(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SubdomainEnumeration failed: %v", err), err
		}

		onLog(fmt.Sprintf("SubdomainEnumeration completed. Found %d results", len(results)))
		resultOutput["subdomain_enumeration_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "os_command_injection") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting OSCommandInjection on: %s", target))

		tester := modules.NewOSCommandInjection(target)
		if cookies, ok := payload["cookies"].(string); ok {
			tester.SetCookies(cookies)
		}
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("OSCommandInjection failed: %v", err), err
		}

		onLog(fmt.Sprintf("OSCommandInjection completed. Found %d results", len(results)))
		resultOutput["os_command_injection_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "subdomain_takeover_analysis") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SubdomainTakeoverAnalysis on: %s", target))

		tester := modules.NewSubdomainTakeoverAnalysis(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SubdomainTakeoverAnalysis failed: %v", err), err
		}

		onLog(fmt.Sprintf("SubdomainTakeoverAnalysis completed. Found %d results", len(results)))
		resultOutput["subdomain_takeover_analysis_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "csrf_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting CSRFTesting on: %s", target))

		tester := modules.NewCSRFTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("CSRFTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("CSRFTesting completed. Found %d results", len(results)))
		resultOutput["csrf_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "d_o_m_based_xss_analysis") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting DOMBasedXSSAnalysis on: %s", target))

		tester := modules.NewDOMBasedXSSAnalysis(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("DOMBasedXSSAnalysis failed: %v", err), err
		}

		onLog(fmt.Sprintf("DOMBasedXSSAnalysis completed. Found %d results", len(results)))
		resultOutput["d_o_m_based_xss_analysis_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "idor_manipulation") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting IDORManipulation on: %s", target))

		tester := modules.NewIDORManipulation(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("IDORManipulation failed: %v", err), err
		}

		onLog(fmt.Sprintf("IDORManipulation completed. Found %d results", len(results)))
		resultOutput["idor_manipulation_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "port_scanning") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting PortScanning on: %s", target))

		tester := modules.NewPortScanning(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("PortScanning failed: %v", err), err
		}

		onLog(fmt.Sprintf("PortScanning completed. Found %d results", len(results)))
		resultOutput["port_scanning_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "s_a_m_l_assertion_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SAMLAssertionTesting on: %s", target))

		tester := modules.NewSAMLAssertionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SAMLAssertionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("SAMLAssertionTesting completed. Found %d results", len(results)))
		resultOutput["s_a_m_l_assertion_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "sql_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SQLInjectionTesting on: %s", target))

		tester := modules.NewSQLInjectionTesting(target)
		if cookies, ok := payload["cookies"].(string); ok {
			tester.SetCookies(cookies)
		}
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SQLInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("SQLInjectionTesting completed. Found %d results", len(results)))
		resultOutput["sql_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "mass_assignment_injection") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting MassAssignmentInjection on: %s", target))

		tester := modules.NewMassAssignmentInjection(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("MassAssignmentInjection failed: %v", err), err
		}

		onLog(fmt.Sprintf("MassAssignmentInjection completed. Found %d results", len(results)))
		resultOutput["mass_assignment_injection_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "token_entropy_analysis") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting TokenEntropyAnalysis on: %s", target))

		tester := modules.NewTokenEntropyAnalysis(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("TokenEntropyAnalysis failed: %v", err), err
		}

		onLog(fmt.Sprintf("TokenEntropyAnalysis completed. Found %d results", len(results)))
		resultOutput["token_entropy_analysis_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "ssrf_exploitation") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SSRFExploitation on: %s", target))

		tester := modules.NewSSRFExploitation(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SSRFExploitation failed: %v", err), err
		}

		onLog(fmt.Sprintf("SSRFExploitation completed. Found %d results", len(results)))
		resultOutput["ssrf_exploitation_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "replacive_fuzzing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting ReplaciveFuzzing on: %s", target))

		tester := modules.NewReplaciveFuzzing(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("ReplaciveFuzzing failed: %v", err), err
		}

		onLog(fmt.Sprintf("ReplaciveFuzzing completed. Found %d results", len(results)))
		resultOutput["replacive_fuzzing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "ldap_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting LDAPInjectionTesting on: %s", target))

		tester := modules.NewLDAPInjectionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("LDAPInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("LDAPInjectionTesting completed. Found %d results", len(results)))
		resultOutput["ldap_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "ssi_injection_testing") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting SsiInjectionTesting on: %s", target))

		tester := modules.NewSsiInjectionTesting(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("SsiInjectionTesting failed: %v", err), err
		}

		onLog(fmt.Sprintf("SsiInjectionTesting completed. Found %d results", len(results)))
		resultOutput["ssi_injection_testing_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "broken_object_level_authorization_bola") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting BrokenObjectLevelAuthorizationBola on: %s", target))

		tester := modules.NewBrokenObjectLevelAuthorizationBola(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("BrokenObjectLevelAuthorizationBola failed: %v", err), err
		}

		onLog(fmt.Sprintf("BrokenObjectLevelAuthorizationBola completed. Found %d results", len(results)))
		resultOutput["broken_object_level_authorization_bola_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "password_spraying") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting PasswordSpraying on: %s", target))

		tester := modules.NewPasswordSpraying(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("PasswordSpraying failed: %v", err), err
		}

		onLog(fmt.Sprintf("PasswordSpraying completed. Found %d results", len(results)))
		resultOutput["password_spraying_results"] = results
	}

	if strings.Contains(strings.ToLower(decision.Technique), "broken_function_level_authorization_bfla") {
		target := payload["url"].(string)
		onLog(fmt.Sprintf("Starting BrokenFunctionLevelAuthorizationBfla on: %s", target))

		tester := modules.NewBrokenFunctionLevelAuthorizationBfla(target)
		results, err := tester.Execute(context.Background())
		if err != nil {
			return fmt.Sprintf("BrokenFunctionLevelAuthorizationBfla failed: %v", err), err
		}

		onLog(fmt.Sprintf("BrokenFunctionLevelAuthorizationBfla completed. Found %d results", len(results)))
		resultOutput["broken_function_level_authorization_bfla_results"] = results
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
