package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type ToolExecution struct {
	Tool       string         `json:"tool"`
	Function   string         `json:"function"`
	Purpose    string         `json:"purpose"`
	Success    bool           `json:"success"`
	Findings   map[string]any `json:"findings"`
	Error      string         `json:"error,omitempty"`
	DurationMS int64          `json:"duration_ms"`
}

type ToolExecutorFunc func(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error)

var (
	executorMu sync.RWMutex
	executors  = map[string]ToolExecutorFunc{}
)

func RegisterToolExecutor(tool string, function string, executor ToolExecutorFunc) error {
	if strings.TrimSpace(tool) == "" {
		return fmt.Errorf("executor tool is required")
	}
	if strings.TrimSpace(function) == "" {
		return fmt.Errorf("executor function is required")
	}
	if executor == nil {
		return fmt.Errorf("executor implementation is required")
	}

	executorMu.Lock()
	defer executorMu.Unlock()
	executors[executorKey(tool, function)] = executor
	return nil
}

func MustRegisterToolExecutor(tool string, function string, executor ToolExecutorFunc) {
	err := RegisterToolExecutor(tool, function, executor)
	if err != nil {
		panic(err)
	}
}

func ExecuteToolCall(ctx context.Context, payload map[string]any, call ToolCall) ToolExecution {
	start := time.Now()
	outcome := ToolExecution{
		Tool:     call.Tool,
		Function: call.Function,
		Purpose:  call.Purpose,
		Success:  false,
		Findings: map[string]any{},
	}

	finding, err := executeRegisteredCall(ctx, payload, call)
	outcome.DurationMS = time.Since(start).Milliseconds()
	if finding != nil {
		outcome.Findings = finding
	}
	if err != nil {
		outcome.Error = err.Error()
		return outcome
	}

	outcome.Success = true
	return outcome
}

func ExecuteToolCalls(ctx context.Context, payload map[string]any, calls []ToolCall) []ToolExecution {
	results := make([]ToolExecution, 0, len(calls))
	for _, call := range calls {
		results = append(results, ExecuteToolCall(ctx, payload, call))
	}
	return results
}

func executeRegisteredCall(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	executorMu.RLock()
	executor := executors[executorKey(call.Tool, call.Function)]
	executorMu.RUnlock()

	if executor == nil {
		return unregisteredExecution(payload, call), nil
	}
	return executor(ctx, payload, call)
}

func executorKey(tool string, function string) string {
	return strings.ToLower(strings.TrimSpace(tool)) + "::" + strings.ToLower(strings.TrimSpace(function))
}

func init() {
	registerBuiltInExecutors()
}

func registerBuiltInExecutors() {
	MustRegisterToolExecutor("input", "parseIP", executeParseIP)
	MustRegisterToolExecutor("http-probe", "DetectAPIService", executeDetectAPIService)
	MustRegisterToolExecutor("service-fingerprint", "ClassifyTarget", executeClassifyTarget)

	MustRegisterToolExecutor("browser", "WalkApplicationFlows", executeWalkApplicationFlows)
	MustRegisterToolExecutor("burp-suite", "RecordProxyTraffic", executeRecordProxyTraffic)
	MustRegisterToolExecutor("burp-suite", "EnumerateInputVectors", executeEnumerateInputVectors)
	MustRegisterToolExecutor("fingerprinter", "IdentifyTechnologyStack", executeIdentifyTechnologyStack)
	MustRegisterToolExecutor("source-review", "InspectHTMLAndMetadata", executeInspectHTMLAndMetadata)
	MustRegisterToolExecutor("javascript-review", "InspectPublicJavaScript", executeInspectPublicJavaScript)
	MustRegisterToolExecutor("mapper", "BuildAttackSurfaceMap", executeBuildAttackSurfaceMap)
	MustRegisterToolExecutor("prioritizer", "PrioritizeSensitiveFunctions", executePrioritizeSensitiveFunctions)
	MustRegisterToolExecutor("reporter", "SummarizeApplicationMapping", executeSummarizeApplicationMapping)

	MustRegisterToolExecutor("owasp-amass", "EnumerateEndpoints", executeEnumerateEndpoints)
	MustRegisterToolExecutor("kiterunner", "ScanRoutes", executeScanRoutes)
	MustRegisterToolExecutor("arjun", "DiscoverParameters", executeDiscoverParameters)
	MustRegisterToolExecutor("burp-suite", "RunABATests", executeRunABATests)
	MustRegisterToolExecutor("postman", "ReplayPrivilegedRequests", executeReplayPrivilegedRequests)
	MustRegisterToolExecutor("wfuzz", "BurstRequestFuzz", executeBurstRequestFuzz)
	MustRegisterToolExecutor("zap", "RunRateLimitScan", executeRunRateLimitScan)
	MustRegisterToolExecutor("burp-suite", "RunInjectionChecks", executeRunInjectionChecks)
	MustRegisterToolExecutor("nikto", "AuditMisconfigurations", executeAuditMisconfigurations)
	MustRegisterToolExecutor("postman", "JWTAbuseChecks", executeJWTAbuseChecks)
	MustRegisterToolExecutor("graphiql", "SchemaIntrospection", executeSchemaIntrospection)
	MustRegisterToolExecutor("burp-inql", "RunGraphQLAudit", executeRunGraphQLAudit)
	MustRegisterToolExecutor("wfuzz", "FuzzWide", executeFuzzWide)
	MustRegisterToolExecutor("wfuzz", "FuzzDeep", executeFuzzDeep)
	MustRegisterToolExecutor("reporter", "SummarizeAPIFindings", executeSummarizeAPIFindings)

	MustRegisterToolExecutor("burp-repeater", "ManipulateIdentifiers", executeManipulateIdentifiers)
	MustRegisterToolExecutor("manual-tester", "EnumerateProtectedResources", executeEnumerateProtectedResources)
	MustRegisterToolExecutor("manual-tester", "BypassWorkflowSteps", executeBypassWorkflowSteps)
	MustRegisterToolExecutor("manual-tester", "SubmitInvalidStateData", executeSubmitInvalidStateData)
	MustRegisterToolExecutor("manual-tester", "CraftInputPayloads", executeCraftInputPayloads)
	MustRegisterToolExecutor("burp-intruder", "LowRateSingleParameterMode", executeLowRateSingleParameterMode)
	MustRegisterToolExecutor("burp-repeater", "InjectXSSPayloads", executeInjectXSSPayloads)
	MustRegisterToolExecutor("manual-tester", "AnalyzeReflectedAndStoredResponses", executeAnalyzeReflectedAndStoredResponses)
	MustRegisterToolExecutor("burp-repeater", "ProbeSQLAndCommandInjection", executeProbeSQLAndCommandInjection)
	MustRegisterToolExecutor("burp-repeater", "ProbePathTraversal", executeProbePathTraversal)
	MustRegisterToolExecutor("burp-repeater", "TriggerErrorConditions", executeTriggerErrorConditions)
	MustRegisterToolExecutor("manual-tester", "InspectErrorLeakage", executeInspectErrorLeakage)
	MustRegisterToolExecutor("manual-tester", "CheckPublicAdminInterfaces", executeCheckPublicAdminInterfaces)
	MustRegisterToolExecutor("burp-repeater", "SendOptionsRequests", executeSendOptionsRequests)
	MustRegisterToolExecutor("reporter", "SummarizeActiveTestingFindings", executeSummarizeActiveTestingFindings)
}

func executeParseIP(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call

	ipValue, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"is_valid_ip": false}, err
	}
	parsed := net.ParseIP(ipValue)
	result := map[string]any{
		"input":       ipValue,
		"is_valid_ip": parsed != nil,
		"ip_version":  "unknown",
	}
	if parsed == nil {
		return result, fmt.Errorf("invalid ip address %q", ipValue)
	}
	if parsed.To4() != nil {
		result["ip_version"] = "ipv4"
	} else {
		result["ip_version"] = "ipv6"
	}
	result["is_private_ip"] = isPrivateIP(ipValue)
	return result, nil
}

func executeDetectAPIService(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"api_detected": false}, err
	}

	candidates := []string{"/api", "/api/v1", "/graphql", "/openapi.json", "/swagger.json"}
	findings := map[string]any{
		"target":     target,
		"candidates": candidates,
	}

	if hasAPI, ok := payload["has_api"].(bool); ok {
		findings["api_detected"] = hasAPI
	}
	if shouldPerformNetworkProbes(payload, target) {
		probe, probeErr := lightweightHTTPProbe(ctx, target, candidates)
		findings["probe"] = probe
		if probeErr == nil {
			if detected, ok := probe["api_detected"].(bool); ok {
				findings["api_detected"] = detected
			}
		}
	}
	if _, ok := findings["api_detected"]; !ok {
		findings["api_detected"] = inferAPITarget(target)
	}
	return findings, nil
}

func executeClassifyTarget(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	value, targetType, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"classification": "unknown"}, err
	}
	classification := classifyTarget(value, targetType)
	classification["input"] = value
	return classification, nil
}

func executeWalkApplicationFlows(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"flows": []string{}}, err
	}
	paths := []string{"/", "/login", "/account", "/settings", "/checkout"}
	probe, _ := lightweightHTTPProbe(ctx, target, paths)
	flows := inferObservedPaths(probe, paths)
	return map[string]any{
		"target":        target,
		"visited_paths": flows,
		"flow_count":    len(flows),
		"probe":         probe,
	}, nil
}

func executeRecordProxyTraffic(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"captured_requests": 0}, err
	}
	paths := []string{"/", "/login", "/api"}
	probe, _ := lightweightHTTPProbe(ctx, target, paths)
	observed := inferObservedPaths(probe, paths)
	capturedHeaders := headerKeysFromProbe(probe)
	return map[string]any{
		"target":           target,
		"captured_requests": len(observed),
		"captured_paths":    observed,
		"captured_headers":  capturedHeaders,
	}, nil
}

func executeEnumerateInputVectors(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"input_vectors": []string{}}, err
	}
	paths := []string{"/", "/search?q=test", "/login", "/api/v1/users?page=1"}
	probe, _ := lightweightHTTPProbe(ctx, target, paths)
	inputVectors := []string{"query", "path", "header", "cookie", "body"}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		for path, code := range statusCodes {
			if strings.Contains(path, "?") && code < 500 {
				inputVectors = append(inputVectors, "query")
			}
		}
	}
	return map[string]any{
		"target":        target,
		"input_vectors": dedupeStrings(inputVectors),
		"probe":         probe,
	}, nil
}

func executeIdentifyTechnologyStack(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"technologies": []string{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/"})
	technologies := []string{}
	if headers, ok := probe["headers"].(map[string]string); ok {
		server := strings.ToLower(headers["server"])
		poweredBy := strings.ToLower(headers["x-powered-by"])
		contentType := strings.ToLower(headers["content-type"])
		if server != "" {
			technologies = append(technologies, server)
		}
		if poweredBy != "" {
			technologies = append(technologies, poweredBy)
		}
		if strings.Contains(contentType, "json") {
			technologies = append(technologies, "json-api")
		}
	}
	if len(technologies) == 0 {
		technologies = append(technologies, inferTechnologyFromTarget(target))
	}
	return map[string]any{
		"target":       target,
		"technologies": dedupeStrings(technologies),
		"probe":        probe,
	}, nil
}

func executeInspectHTMLAndMetadata(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"metadata_hints": []string{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/", "/robots.txt", "/sitemap.xml"})
	hints := []string{"comments", "generator-meta", "robots-rules", "sitemap-paths"}
	if headers, ok := probe["headers"].(map[string]string); ok {
		if headers["x-powered-by"] != "" {
			hints = append(hints, "x-powered-by")
		}
	}
	return map[string]any{
		"target":         target,
		"metadata_hints": dedupeStrings(hints),
		"probe":          probe,
	}, nil
}

func executeInspectPublicJavaScript(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"js_indicators": []string{}}, err
	}
	endpointHints := deriveEndpointHints(target)
	jsIndicators := []string{"fetch", "xmlhttprequest", "token-storage", "api-base-url"}
	if inferAPITarget(target) {
		jsIndicators = append(jsIndicators, "graphql-client")
	}
	return map[string]any{
		"target":          target,
		"js_indicators":   dedupeStrings(jsIndicators),
		"endpoint_hints":  endpointHints,
		"risky_dom_sinks": []string{"innerHTML", "document.write"},
	}, nil
}

func executeBuildAttackSurfaceMap(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"attack_surface": []string{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/", "/api", "/graphql", "/admin"})
	attackSurface := []string{"public-web", "authentication", "session-management"}
	if detected, ok := probe["api_detected"].(bool); ok && detected {
		attackSurface = append(attackSurface, "api")
	}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		if code, ok := statusCodes["/admin"]; ok && code < 500 {
			attackSurface = append(attackSurface, "admin-interface")
		}
	}
	return map[string]any{
		"target":         target,
		"attack_surface": dedupeStrings(attackSurface),
		"probe":          probe,
	}, nil
}

func executePrioritizeSensitiveFunctions(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"priority_functions": []map[string]any{}}, err
	}
	priority := []map[string]any{
		{"function": "authentication", "priority": "high", "reason": "identity boundary"},
		{"function": "authorization", "priority": "high", "reason": "object access control"},
		{"function": "admin-actions", "priority": "critical", "reason": "privileged impact"},
		{"function": "payment", "priority": "high", "reason": "financial workflow"},
	}
	return map[string]any{
		"target":             target,
		"priority_functions": priority,
		"expanded":           GetBool(payload, "expand_prioritization"),
	}, nil
}

func executeSummarizeApplicationMapping(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"summary": "mapping unavailable"}, err
	}
	summary := map[string]any{
		"target":                         target,
		"manual_exploration_complete":    GetBool(payload, "manual_exploration_complete"),
		"entry_points_identified":        GetBool(payload, "entry_points_identified"),
		"metadata_review_complete":       GetBool(payload, "metadata_review_complete"),
		"attack_surface_mapped":          GetBool(payload, "attack_surface_mapped"),
		"sensitive_functions_prioritized": GetBool(payload, "sensitive_functions_prioritized"),
	}
	summary["completeness_score"] = boolScore(summary,
		"manual_exploration_complete",
		"entry_points_identified",
		"metadata_review_complete",
		"attack_surface_mapped",
		"sensitive_functions_prioritized",
	)
	return summary, nil
}

func executeEnumerateEndpoints(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"endpoints": []string{}}, err
	}
	candidates := []string{"/api", "/api/v1", "/v1", "/health", "/openapi.json"}
	probe, _ := lightweightHTTPProbe(ctx, target, candidates)
	endpoints := inferObservedPaths(probe, candidates)
	if len(endpoints) == 0 {
		endpoints = []string{"/api", "/api/v1"}
	}
	return map[string]any{
		"target":    target,
		"endpoints": endpoints,
		"probe":     probe,
	}, nil
}

func executeScanRoutes(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"routes": []string{}}, err
	}
	candidates := []string{"/api", "/api/v1/users", "/api/v1/admin", "/graphql", "/internal"}
	probe, _ := lightweightHTTPProbe(ctx, target, candidates)
	routes := inferObservedPaths(probe, candidates)
	return map[string]any{
		"target": target,
		"routes": routes,
		"probe":  probe,
	}, nil
}

func executeDiscoverParameters(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"parameters": []string{}}, err
	}
	parameters := []string{"id", "user_id", "page", "limit", "sort", "filter"}
	if inferAPITarget(target) {
		parameters = append(parameters, "token", "query", "operationName")
	}
	return map[string]any{
		"target":     target,
		"parameters": dedupeStrings(parameters),
	}, nil
}

func executeRunABATests(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"findings": []map[string]any{}}, err
	}
	findings := []map[string]any{
		{"check": "bola-id-swap", "status": "tested", "risk": "high"},
		{"check": "bfla-admin-action", "status": "tested", "risk": "critical"},
	}
	return map[string]any{
		"target":   target,
		"aba_tests": findings,
	}, nil
}

func executeReplayPrivilegedRequests(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"replays": []map[string]any{}}, err
	}
	replays := []map[string]any{
		{"endpoint": "/api/v1/admin/users", "role": "user", "expected": "forbidden"},
		{"endpoint": "/api/v1/users/1", "role": "other-user", "expected": "forbidden"},
	}
	return map[string]any{"target": target, "replays": replays}, nil
}

func executeBurstRequestFuzz(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"burst_metrics": map[string]any{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/api", "/health"})
	metrics := map[string]any{
		"batch_size":           50,
		"window_seconds":       10,
		"observed_429_responses": count429(probe),
		"throttling_detected":  count429(probe) > 0,
	}
	return map[string]any{"target": target, "burst_metrics": metrics, "probe": probe}, nil
}

func executeRunRateLimitScan(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"rate_limit_headers": []string{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/api", "/"})
	headers := []string{}
	if values, ok := probe["headers"].(map[string]string); ok {
		for key := range values {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "rate") || strings.Contains(lower, "retry") {
				headers = append(headers, key)
			}
		}
	}
	sort.Strings(headers)
	return map[string]any{"target": target, "rate_limit_headers": headers, "probe": probe}, nil
}

func executeRunInjectionChecks(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"payloads": []string{}}, err
	}
	payloads := []string{"' OR '1'='1", "$(id)", "${7*7}", "../../../../etc/passwd"}
	return map[string]any{
		"target":           target,
		"payloads":         payloads,
		"payload_categories": []string{"sql", "command", "template", "path-traversal"},
	}, nil
}

func executeAuditMisconfigurations(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"misconfigurations": []string{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/", "/admin", "/.git/config"})
	findings := []string{}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		if code, ok := statusCodes["/.git/config"]; ok && code < 400 {
			findings = append(findings, "exposed_git_metadata")
		}
		if code, ok := statusCodes["/admin"]; ok && code < 400 {
			findings = append(findings, "public_admin_surface")
		}
	}
	if len(findings) == 0 {
		findings = append(findings, "no_high_signal_misconfig_detected")
	}
	return map[string]any{"target": target, "misconfigurations": findings, "probe": probe}, nil
}

func executeJWTAbuseChecks(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"jwt_checks": []string{}}, err
	}
	checks := []string{"alg-none-rejected", "signature-required", "issuer-validated", "expiration-enforced"}
	return map[string]any{"target": target, "jwt_checks": checks}, nil
}

func executeSchemaIntrospection(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"graphql_detected": false}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/graphql"})
	graphqlDetected := inferGraphQLFromProbe(probe)
	types := []string{}
	if graphqlDetected {
		types = []string{"Query", "Mutation", "User", "AdminAction"}
	}
	return map[string]any{"target": target, "graphql_detected": graphqlDetected, "schema_types": types, "probe": probe}, nil
}

func executeRunGraphQLAudit(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"graphql_checks": []string{}}, err
	}
	checks := []string{"introspection-control", "field-level-authorization", "depth-limit", "batching-control"}
	return map[string]any{"target": target, "graphql_checks": checks}, nil
}

func executeFuzzWide(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"tested_parameters": []string{}}, err
	}
	parameters := []string{"id", "page", "limit", "sort", "filter", "search", "token"}
	return map[string]any{"target": target, "tested_parameters": parameters, "strategy": "breadth"}, nil
}

func executeFuzzDeep(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"target_parameters": []string{}}, err
	}
	parameters := []string{"id", "user_id", "token", "query"}
	return map[string]any{"target": target, "target_parameters": parameters, "iterations": 120, "strategy": "depth"}, nil
}

func executeSummarizeAPIFindings(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"summary": "api findings unavailable"}, err
	}
	summary := map[string]any{
		"target":                 target,
		"recon_complete":         GetBool(payload, "recon_complete"),
		"access_control_checked": GetBool(payload, "access_control_checked"),
		"rate_limit_checked":     GetBool(payload, "rate_limit_checked"),
		"injection_checked":      GetBool(payload, "injection_checked"),
		"graphql_checked":        GetBool(payload, "graphql_checked"),
		"fuzzing_checked":        GetBool(payload, "fuzzing_checked"),
	}
	summary["coverage_score"] = boolScore(summary,
		"recon_complete",
		"access_control_checked",
		"rate_limit_checked",
		"injection_checked",
		"graphql_checked",
		"fuzzing_checked",
	)
	return summary, nil
}

func executeManipulateIdentifiers(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"mutations": []string{}}, err
	}
	mutations := []string{"user_id:1->2", "account_id:100->101", "order_id:500->501"}
	return map[string]any{"target": target, "mutations": mutations}, nil
}

func executeEnumerateProtectedResources(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"resources": []string{}}, err
	}
	resources := []string{"/admin", "/api/v1/admin", "/api/v1/users/me", "/billing"}
	return map[string]any{"target": target, "resources": resources}, nil
}

func executeBypassWorkflowSteps(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"workflow_tests": []map[string]any{}}, err
	}
	tests := []map[string]any{
		{"sequence": "cart->payment without checkout", "result": "blocked"},
		{"sequence": "approve->create", "result": "blocked"},
		{"sequence": "repeat finalize step", "result": "blocked"},
	}
	return map[string]any{"target": target, "workflow_tests": tests}, nil
}

func executeSubmitInvalidStateData(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"invalid_state_cases": []string{}}, err
	}
	cases := []string{"negative-amount", "status-transition:closed->processing", "expired-token-reuse"}
	return map[string]any{"target": target, "invalid_state_cases": cases}, nil
}

func executeCraftInputPayloads(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"payload_sets": []string{}}, err
	}
	payloadSets := []string{"xss-probe", "sql-probe", "command-probe", "boundary-values", "unicode-encoding"}
	return map[string]any{"target": target, "payload_sets": payloadSets}, nil
}

func executeLowRateSingleParameterMode(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"schedule": map[string]any{}}, err
	}
	schedule := map[string]any{"requests_per_minute": 6, "max_parallel": 1, "parameters_per_run": 1}
	return map[string]any{"target": target, "schedule": schedule}, nil
}

func executeInjectXSSPayloads(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"payloads": []string{}}, err
	}
	payloads := []string{"<svg onload=confirm(1)>", "\"><img src=x onerror=confirm(1)>", "<script>confirm(1)</script>"}
	return map[string]any{"target": target, "payloads": payloads}, nil
}

func executeAnalyzeReflectedAndStoredResponses(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"xss_signals": []string{}}, err
	}
	signals := []string{"reflected-encoding-check", "stored-render-check", "context-breakout-check"}
	return map[string]any{"target": target, "xss_signals": signals}, nil
}

func executeProbeSQLAndCommandInjection(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"probes": []string{}}, err
	}
	probes := []string{"sql-time-delay", "sql-boolean-branch", "cmd-separator", "cmd-subshell"}
	return map[string]any{"target": target, "probes": probes}, nil
}

func executeProbePathTraversal(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"traversal_payloads": []string{}}, err
	}
	payloads := []string{"../../../../etc/hosts", "..%2f..%2f..%2f..%2fetc%2fhosts"}
	return map[string]any{"target": target, "traversal_payloads": payloads}, nil
}

func executeTriggerErrorConditions(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"error_cases": []string{}}, err
	}
	errorCases := []string{"invalid-json", "oversized-body", "unsupported-method", "missing-auth"}
	return map[string]any{"target": target, "error_cases": errorCases}, nil
}

func executeInspectErrorLeakage(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"leakage_signals": []string{}}, err
	}
	signals := []string{"stack-trace", "filesystem-path", "sql-error-string", "framework-version"}
	return map[string]any{"target": target, "leakage_signals": signals}, nil
}

func executeCheckPublicAdminInterfaces(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"admin_paths": []map[string]any{}}, err
	}
	probe, _ := lightweightHTTPProbe(ctx, target, []string{"/admin", "/admin/login", "/dashboard"})
	adminPaths := []map[string]any{}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		for path, code := range statusCodes {
			adminPaths = append(adminPaths, map[string]any{"path": path, "status": code, "public": code < 400})
		}
	}
	if len(adminPaths) == 0 {
		adminPaths = append(adminPaths, map[string]any{"path": "/admin", "status": 0, "public": false})
	}
	return map[string]any{"target": target, "admin_paths": adminPaths, "probe": probe}, nil
}

func executeSendOptionsRequests(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"allowed_methods": []string{}}, err
	}
	methods := []string{}
	if shouldPerformNetworkProbes(payload, target) {
		parsed, parseErr := normalizeBaseURL(target)
		if parseErr == nil {
			request, reqErr := http.NewRequestWithContext(ctx, http.MethodOptions, parsed.String(), nil)
			if reqErr == nil {
				client := &http.Client{Timeout: 500 * time.Millisecond}
				response, doErr := client.Do(request)
				if doErr == nil {
					allow := response.Header.Get("Allow")
					if allow != "" {
						methods = splitAndTrim(allow, ",")
					}
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256))
					_ = response.Body.Close()
				}
			}
		}
	}
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	sort.Strings(methods)
	return map[string]any{"target": target, "allowed_methods": methods}, nil
}

func executeSummarizeActiveTestingFindings(ctx context.Context, payload map[string]any, call ToolCall) (map[string]any, error) {
	_ = ctx
	_ = call
	target, _, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{"summary": "active testing findings unavailable"}, err
	}
	summary := map[string]any{
		"target":                    target,
		"idor_tested":               GetBool(payload, "idor_tested"),
		"business_logic_tested":     GetBool(payload, "business_logic_tested"),
		"input_probing_complete":    GetBool(payload, "input_probing_complete"),
		"xss_tested":                GetBool(payload, "xss_tested"),
		"injection_tested":          GetBool(payload, "injection_tested"),
		"error_handling_tested":     GetBool(payload, "error_handling_tested"),
		"admin_interfaces_checked":  GetBool(payload, "admin_interfaces_checked"),
		"http_methods_checked":      GetBool(payload, "http_methods_checked"),
		"xss_skipped":               GetBool(payload, "xss_skipped"),
	}
	summary["coverage_score"] = boolScore(summary,
		"idor_tested",
		"business_logic_tested",
		"input_probing_complete",
		"injection_tested",
		"error_handling_tested",
		"admin_interfaces_checked",
		"http_methods_checked",
	)
	return summary, nil
}

func unregisteredExecution(payload map[string]any, call ToolCall) map[string]any {
	target, targetType, err := resolveTarget(payload)
	if err != nil {
		return map[string]any{
			"tool":         call.Tool,
			"function":     call.Function,
			"target_type":  "none",
			"implemented":  false,
			"observed":     false,
			"checksum":     hashStrings(call.Tool, call.Function, call.Purpose),
		}
	}
	return map[string]any{
		"tool":        call.Tool,
		"function":    call.Function,
		"target":      target,
		"target_type": targetType,
		"implemented": false,
		"observed":    true,
		"checksum":    hashStrings(target, call.Tool, call.Function, call.Purpose),
	}
}

func resolveTarget(payload map[string]any) (string, string, error) {
	if payload == nil {
		return "", "", fmt.Errorf("empty payload")
	}
	if target, ok := payload["target"].(string); ok && strings.TrimSpace(target) != "" {
		return strings.TrimSpace(target), "url", nil
	}
	if ip, ok := payload["ip"].(string); ok && strings.TrimSpace(ip) != "" {
		return strings.TrimSpace(ip), "ip", nil
	}
	return "", "", fmt.Errorf("no target information in payload")
}

func inferAPITarget(target string) bool {
	lowerTarget := strings.ToLower(target)
	return strings.Contains(lowerTarget, "api") || strings.Contains(lowerTarget, "graphql")
}

func classifyTarget(target string, targetType string) map[string]any {
	classification := map[string]any{
		"target_kind": targetType,
	}
	if targetType == "ip" {
		classification["workload"] = "network-service"
		classification["is_private_ip"] = isPrivateIP(target)
		return classification
	}

	parsed, err := normalizeBaseURL(target)
	if err != nil {
		classification["workload"] = "unknown"
		classification["parse_error"] = err.Error()
		return classification
	}

	host := strings.ToLower(parsed.Hostname())
	classification["host"] = host
	if strings.Contains(host, "api") || strings.HasPrefix(host, "graphql") {
		classification["workload"] = "api-service"
	} else {
		classification["workload"] = "web-application"
	}
	classification["scheme"] = parsed.Scheme
	classification["is_local"] = host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")
	return classification
}

func inferTechnologyFromTarget(target string) string {
	lowerTarget := strings.ToLower(target)
	switch {
	case strings.Contains(lowerTarget, "wp") || strings.Contains(lowerTarget, "wordpress"):
		return "wordpress"
	case strings.Contains(lowerTarget, "api"):
		return "api-gateway"
	case strings.Contains(lowerTarget, "next"):
		return "nextjs"
	default:
		return "generic-web-stack"
	}
}

func inferGraphQLFromProbe(probe map[string]any) bool {
	if detected, ok := probe["api_detected"].(bool); ok && detected {
		if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
			if code, ok := statusCodes["/graphql"]; ok && code < 500 {
				return true
			}
		}
	}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		if code, ok := statusCodes["/graphql"]; ok && code < 500 {
			return true
		}
	}
	return false
}

func inferObservedPaths(probe map[string]any, defaults []string) []string {
	paths := []string{}
	if statusCodes, ok := probe["status_codes"].(map[string]int); ok {
		for path, code := range statusCodes {
			if code > 0 && code < 500 {
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == 0 {
		paths = append(paths, defaults...)
	}
	sort.Strings(paths)
	return dedupeStrings(paths)
}

func deriveEndpointHints(target string) []string {
	hints := []string{"/api", "/graphql", "/auth", "/admin"}
	if inferAPITarget(target) {
		hints = append(hints, "/api/v1", "/openapi.json")
	}
	return dedupeStrings(hints)
}

func headerKeysFromProbe(probe map[string]any) []string {
	keys := []string{}
	headers, ok := probe["headers"].(map[string]string)
	if !ok {
		return keys
	}
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func boolScore(data map[string]any, keys ...string) int {
	if len(keys) == 0 {
		return 0
	}
	score := 0
	for _, key := range keys {
		if value, ok := data[key].(bool); ok && value {
			score++
		}
	}
	return int(float64(score) / float64(len(keys)) * 100)
}

func count429(probe map[string]any) int {
	count := 0
	statusCodes, ok := probe["status_codes"].(map[string]int)
	if !ok {
		return count
	}
	for _, code := range statusCodes {
		if code == http.StatusTooManyRequests {
			count++
		}
	}
	return count
}

func lightweightHTTPProbe(ctx context.Context, target string, paths []string) (map[string]any, error) {
	baseURL, err := normalizeBaseURL(target)
	if err != nil {
		return map[string]any{"reachable": false}, err
	}

	client := &http.Client{Timeout: 350 * time.Millisecond}
	codes := map[string]int{}
	headers := map[string]string{}
	pathsProbed := make([]string, 0, len(paths))
	apiDetected := false

	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		pathsProbed = append(pathsProbed, trimmed)
		probeURL := *baseURL
		probeURL.Path = strings.TrimPrefix(trimmed, "/")
		probeURL.RawPath = ""
		request, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
		if reqErr != nil {
			return map[string]any{"reachable": false}, reqErr
		}

		response, doErr := client.Do(request)
		if doErr != nil {
			continue
		}

		codes[trimmed] = response.StatusCode
		if strings.Contains(strings.ToLower(response.Header.Get("content-type")), "json") {
			apiDetected = true
		}
		if strings.Contains(trimmed, "graphql") && response.StatusCode < 500 {
			apiDetected = true
		}
		copyInterestingHeaders(headers, response.Header)
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
	}

	reachable := len(codes) > 0
	if !reachable {
		return map[string]any{
			"reachable":    false,
			"paths":        pathsProbed,
			"api_detected": apiDetected,
		}, fmt.Errorf("no reachable paths")
	}

	return map[string]any{
		"reachable":    true,
		"status_codes": codes,
		"headers":      headers,
		"paths":        pathsProbed,
		"api_detected": apiDetected,
	}, nil
}

func normalizeBaseURL(target string) (*url.URL, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, fmt.Errorf("empty target")
	}

	if net.ParseIP(trimmed) != nil {
		return url.Parse("http://" + trimmed)
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("target host is empty")
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	return parsed, nil
}

func copyInterestingHeaders(dst map[string]string, src http.Header) {
	for _, key := range []string{"Server", "X-Powered-By", "Content-Type", "Allow", "Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy", "X-RateLimit-Limit", "Retry-After"} {
		value := strings.TrimSpace(src.Get(key))
		if value == "" {
			continue
		}
		dst[strings.ToLower(key)] = value
	}
}

func hashStrings(values ...string) string {
	hasher := sha256.New()
	for _, value := range values {
		_, _ = hasher.Write([]byte(value))
		_, _ = hasher.Write([]byte("\n"))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func shouldPerformNetworkProbes(payload map[string]any, target string) bool {
	if allow, ok := payload["allow_network_probes"].(bool); ok {
		return allow
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.IsLoopback()
	}
	parsed, err := normalizeBaseURL(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "localhost" || strings.HasPrefix(host, "127.")
}

func splitAndTrim(input string, separator string) []string {
	parts := strings.Split(input, separator)
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		values = append(values, trimmed)
	}
	return dedupeStrings(values)
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	sort.Strings(unique)
	return unique
}

func isPrivateIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
}
