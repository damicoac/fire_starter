package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"charm.land/fantasy"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
)

// agentEnv carries the dependencies shared by the orchestration loop, the
// per-target agent loop, and the vulnerability helper sub-agents. It replaces
// the former long parameter lists on runTargetAgent and
// runVulnerabilityHelperSubAgent.
//
// currentTarget tracks the target the active loop is operating on so
// dispatchToolCall can resolve knowledge-graph queries against the right
// target. It is mutated only by runTargetAgent and
// runVulnerabilityHelperSubAgent, which restore the previous value on return.
// vulnLogged mirrors the helper sub-agent's "finding logged" outcome and is
// reset by every helper run. httpRequestState holds the per-target
// decision_http_request gate bookkeeping while a target loop is active.
type agentEnv struct {
	cfg              Config
	model            fantasy.LanguageModel
	kg               *matrix.KnowledgeGraph
	executor         *matrix.RealExecutor
	decisions        []matrix.Decision
	initialTarget    string
	allowlist        map[string]bool
	toolStageByName  map[string]matrix.Phase
	globalIters      *int
	payloadHashes    map[string]bool
	currentTarget    string
	vulnLogged       bool
	httpRequestState *httpRequestGateState
}

// dispatchToolCall executes a single tool call and returns the result text for
// the LLM transcript. It is the single dispatch site shared by the per-target
// agent loop and the vulnerability helper sub-agent: the target loop passes an
// empty origVulnID, while the helper passes the vuln_id of the finding under
// validation so log_vulnerability updates the original record.
func dispatchToolCall(ctx context.Context, env *agentEnv, call fantasy.ToolCallContent, origVulnID string) (string, error) {
	helperMode := origVulnID != ""

	// Helpers validate findings; only the orchestrator target loop may
	// complete a target. (The target loop intercepts target_completed in
	// splitSubmitToolCall before dispatch, so this only fires for helpers.)
	if helperMode && call.ToolName == "target_completed" {
		return "TOOL_ERROR: helper sub-agent cannot complete the orchestrator target.", nil
	}

	if !helperMode {
		selectedPhase := matrix.PhaseReconnaissance
		if stage, ok := env.toolStageByName[call.ToolName]; ok {
			selectedPhase = stage
		}
		log.Infof("TOOL_SELECTED tool=%s phase=%s", call.ToolName, selectedPhase)
	}

	switch call.ToolName {
	case "advance_target_phase":
		return dispatchAdvanceTargetPhase(env, call, helperMode), nil
	case "log_vulnerability":
		return dispatchLogVulnerability(env, call, origVulnID, helperMode), nil
	case "query_knowledge_graph":
		return dispatchQueryKnowledgeGraph(env, call, env.currentTarget), nil
	}
	return dispatchTechniqueTool(ctx, env, call, helperMode), nil
}

// dispatchAdvanceTargetPhase advances a target to the next red team phase. The
// target loop additionally refuses to leave the exploitation phase while
// candidate findings remain unresolved for that target.
func dispatchAdvanceTargetPhase(env *agentEnv, call fantasy.ToolCallContent, helperMode bool) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Input), &args); err != nil {
		return "TOOL_ERROR: Invalid JSON input."
	}
	tStr, ok := args["target"].(string)
	if !ok || tStr == "" {
		if helperMode {
			return "TOOL_ERROR: Missing target."
		}
		return "TOOL_ERROR: Missing or empty target string."
	}
	normalizedTarget := normalizeTarget(tStr)
	if !helperMode {
		if blocked, reason := blockedByUnresolvedCandidates(env.kg, normalizedTarget); blocked {
			return reason
		}
	}
	newPhase := env.kg.AdvanceTargetPhase(normalizedTarget)
	if helperMode {
		log.Infof("Helper advanced target phase: target=%s new_phase=%s", tStr, newPhase)
	} else {
		log.Infof("TARGET_PHASE_ADVANCED target=%s new_phase=%s", tStr, newPhase)
	}
	return "Target advanced to next phase successfully."
}

// blockedByUnresolvedCandidates reports whether the target still carries
// candidate findings that must be resolved before the exploitation phase can
// be left.
func blockedByUnresolvedCandidates(kg *matrix.KnowledgeGraph, normalizedTarget string) (bool, string) {
	if kg.GetTargetPhase(normalizedTarget) != matrix.PhaseExploitation {
		return false, ""
	}
	vulns, err := matrix.GetVulnerabilities()
	if err != nil {
		return true, fmt.Sprintf("TOOL_ERROR: failed to query vulnerabilities before phase transition: %v", err)
	}
	for _, v := range vulns {
		if normalizeTarget(v.TargetDomain) == normalizedTarget && v.Status == matrix.VulnerabilityStatusCandidate {
			return true, "TOOL_ERROR: cannot advance to post-exploitation while candidate findings remain unresolved for this target. Confirm, mark informational, or disprove each finding first."
		}
	}
	return false, ""
}

// dispatchLogVulnerability logs or updates a resolved finding. Helper mode
// reuses the original vuln_id so the existing record is updated in place.
func dispatchLogVulnerability(env *agentEnv, call fantasy.ToolCallContent, origVulnID string, helperMode bool) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Input), &args); err != nil {
		return "TOOL_ERROR: Invalid JSON input."
	}
	if helperMode {
		return logHelperVulnerability(env, origVulnID, args)
	}
	return logTargetLoopVulnerability(args)
}

// logHelperVulnerability updates the original vulnerability record, keeping
// the vuln_id assigned when the candidate finding was first queued.
func logHelperVulnerability(env *agentEnv, origVulnID string, args map[string]any) string {
	targetStr, okTarget := args["target"].(string)
	fnd, okFnd := args["finding"].(string)
	testCode, okTest := args["test_code"].(string)
	exploitable, okExploit := args["exploitable"].(string)
	status, okStatus := args["status"].(string)
	severity, okSev := args["severity"].(string)

	if !okTarget || !okFnd || !okTest || !okExploit || !okStatus || !okSev {
		return "TOOL_ERROR: Invalid parameter types provided. All parameters must be strings."
	}

	// Update the existing vulnerability record keeping the ID the same
	if validationErr := validateVulnerabilityLogInput(origVulnID, targetStr, fnd, testCode, exploitable, status, severity); validationErr != nil {
		return fmt.Sprintf("TOOL_ERROR: %v", validationErr)
	}
	normalizedTgt := normalizeTarget(targetStr)
	if err := matrix.LogVulnerabilityWithStatus(origVulnID, normalizedTgt, fnd, testCode, exploitable, status, severity); err != nil {
		return fmt.Sprintf("TOOL_ERROR: failed to log vulnerability: %v", err)
	}

	env.vulnLogged = true
	return "Finding logged with resolved status."
}

// logTargetLoopVulnerability logs a new resolved finding, deriving the vuln_id
// from the target and finding text so the naming convention stays consistent.
func logTargetLoopVulnerability(args map[string]any) string {
	targetStr, _ := args["target"].(string)
	finding, _ := args["finding"].(string)
	testCode, _ := args["test_code"].(string)
	exploitable, _ := args["exploitable"].(string)
	status, _ := args["status"].(string)
	severity, _ := args["severity"].(string)

	// Enforce consistent vuln_id naming convention
	vulnID := matrix.GenerateVulnID(targetStr, finding)
	if validationErr := validateVulnerabilityLogInput(vulnID, targetStr, finding, testCode, exploitable, status, severity); validationErr != nil {
		return fmt.Sprintf("TOOL_ERROR: %v", validationErr)
	}
	if err := matrix.LogVulnerabilityWithStatus(vulnID, normalizeTarget(targetStr), finding, testCode, exploitable, status, severity); err != nil {
		return fmt.Sprintf("TOOL_ERROR: failed to log vulnerability: %v", err)
	}
	return "Finding logged with resolved status."
}

// dispatchQueryKnowledgeGraph answers a knowledge-graph intelligence query.
func dispatchQueryKnowledgeGraph(env *agentEnv, call fantasy.ToolCallContent, currentTarget string) string {
	var qArgs map[string]any
	if err := json.Unmarshal([]byte(call.Input), &qArgs); err != nil {
		return "TOOL_ERROR: Invalid JSON input."
	}
	qType, _ := qArgs["query_type"].(string)

	var resBytes []byte
	var err error
	switch qType {
	case "ips":
		resBytes, err = json.Marshal(env.kg.GetIPTargets())
	case "urls":
		resBytes, err = json.Marshal(env.kg.GetURLTargets())
	case "ports":
		resBytes, err = json.Marshal(env.kg.GetTargetPorts())
	case "credentials":
		resBytes, err = json.Marshal(env.kg.GetCredentials())
	case "vulnerabilities":
		vulns, verr := matrix.GetVulnerabilities()
		if verr != nil {
			resBytes, err = json.Marshal(map[string]string{"error": fmt.Sprintf("failed to query vulnerabilities: %v", verr)})
		} else {
			resBytes, err = json.Marshal(vulns)
		}
	case "tokens":
		target, _ := qArgs["target"].(string)
		var tokens []string
		if target != "" {
			tokens = env.kg.GetTokensForTarget(target)
		} else {
			tokens = env.kg.GetTokens()
		}
		resBytes, err = json.Marshal(tokens)
	default:
		resBytes, err = env.kg.ToJSONWithoutTestCases(currentTarget)
	}
	if err != nil {
		resBytes = []byte(fmt.Sprintf("{\"error\": \"failed to marshal result: %v\"}", err))
	}
	return string(resBytes)
}

// dispatchTechniqueTool executes a registered technique module. The payload is
// whitelist-checked, deduplicated, and run across the selected session
// variants; intelligence is extracted from every successful execution.
func dispatchTechniqueTool(ctx context.Context, env *agentEnv, call fantasy.ToolCallContent, helperMode bool) string {
	var args map[string]any
	if call.Input != "" {
		if err := json.Unmarshal([]byte(call.Input), &args); err != nil {
			return fmt.Sprintf("TOOL_ERROR: Failed to parse tool input JSON: %v", err)
		}
	}

	payload := mergeToolPayload(args)

	if len(env.allowlist) > 0 && !isPayloadAllowedByIPWhitelist(payload, env.allowlist) {
		return "TOOL_ERROR: blocked by IP whitelist policy. Allowed IPs: " + allowlistedIPsSummary(env.allowlist)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("Failed to marshal payload: %v", err)
	}
	payloadHash := fmt.Sprintf("%s|%s", call.ToolName, string(payloadBytes))
	isExec, _ := matrix.IsPayloadExecuted(payloadHash)
	if env.payloadHashes[payloadHash] || isExec {
		if helperMode {
			return "TOOL_ERROR: You have already successfully executed this tool with this exact payload in this helper run. Choose different parameters or another tool."
		}
		return "TOOL_ERROR: You have already successfully executed this tool with this exact payload. Please choose a different target, a different tool, different parameters, or advance the phase."
	}

	targetUsed := targetUsedFromPayload(env.initialTarget, payload)
	sessionsToTest := selectSessions(env, call.ToolName, args, targetUsed)

	summaries := executeToolAcrossSessions(ctx, env, call, payload, targetUsed, sessionsToTest, payloadHash, helperMode)
	return fmt.Sprintf("=== TOOL EXECUTION SUMMARY ===\n%s", strings.Join(summaries, "\n\n"))
}

// executeToolAcrossSessions runs one tool payload against every selected
// session variant and collects per-session summaries.
func executeToolAcrossSessions(ctx context.Context, env *agentEnv, call fantasy.ToolCallContent, payload map[string]any, targetUsed string, sessionsToTest []string, payloadHash string, helperMode bool) []string {
	var allSummaries []string

	for _, sess := range sessionsToTest {
		// Clone payload so we don't bleed state between loop iterations
		iterPayload := clonePayload(payload)
		applySessionContext(env, iterPayload, sess, targetUsed)

		resultData, execErr := env.executor.ExecuteByToolName(ctx, call.ToolName, iterPayload, func(s string) {
			log.Debug(s)
		})

		if execErr != nil {
			errStr := fmt.Sprintf("TOOL_ERROR (Session: %s): %v", sess, execErr)
			allSummaries = append(allSummaries, errStr)
			if helperMode {
				log.Debugf("Helper tool execution failed: tool=%s session=%s error=%s", call.ToolName, sess, errStr)
			} else {
				log.Debugf("TOOL_RESULT tool=%s session=%s status=error result=%s", call.ToolName, sess, errStr)
			}
			continue
		}

		env.payloadHashes[payloadHash] = true
		_ = matrix.RecordPayloadExecuted(payloadHash, call.ToolName, targetUsed)
		markToolExecuted(env.kg, iterPayload, call.ToolName)

		var beforeGraph matrix.KnowledgeSnapshot
		if !helperMode {
			beforeGraph = env.kg.Snapshot()
		}

		summary, _, extractErr := env.kg.ExtractIntelligence(ctx, env.model, call.ToolName, targetUsed, iterPayload, resultData)
		if extractErr != nil {
			if helperMode {
				log.Warnf("Helper intelligence extraction failed: %v. Running deterministic structural extraction fallback.", extractErr)
			} else {
				log.Warnf("Intelligence extraction failed: %v. Running deterministic structural extraction fallback.", extractErr)
			}
			env.kg.StructuralExtract(call.ToolName, targetUsed, iterPayload, resultData)
			summary = fmt.Sprintf("Tool executed successfully; LLM extraction failed (%v), structural intelligence extracted.", extractErr)
		}

		if err := matrix.LogExecution(env.initialTarget, resultData); err != nil {
			log.Warnf("Failed to log execution to SQLite: %v", err)
		}

		if helperMode {
			log.Infof("Helper tool execution success: tool=%s session=%s summary=%q", call.ToolName, sess, summary)
		} else {
			afterGraph := env.kg.Snapshot()
			if call.ToolName == "decision_http_request" {
				applyHTTPRequestGate(env)
			}
			log.Infof("KNOWLEDGE_GRAPH_UPDATE tool=%s session=%s delta=%s snapshot=%s", call.ToolName, sess, snapshotDelta(beforeGraph, afterGraph), summarizeSnapshot(afterGraph))
			_, _ = canCompleteTarget(afterGraph, env.currentTarget, env.cfg.EfficiencyMode)
			log.Infof("TOOL_EXECUTION_SUMMARY tool=%s target=%s session=%s summary=%q", call.ToolName, targetUsed, sess, summary)
		}
		allSummaries = append(allSummaries, fmt.Sprintf("[Session: %s] %s", sess, summary))
	}

	return allSummaries
}

// markToolExecuted records tool execution against every target identifier
// present in the payload.
func markToolExecuted(kg *matrix.KnowledgeGraph, payload map[string]any, toolName string) {
	if t, ok := payload["target"].(string); ok && strings.TrimSpace(t) != "" {
		kg.MarkToolExecuted(strings.TrimSpace(t), toolName)
	}
	if u, ok := payload["url"].(string); ok && strings.TrimSpace(u) != "" {
		kg.MarkToolExecuted(strings.TrimSpace(u), toolName)
	}
	if ip, ok := payload["ip"].(string); ok && strings.TrimSpace(ip) != "" {
		kg.MarkToolExecuted(strings.TrimSpace(ip), toolName)
	}
}

// mergeToolPayload flattens a nested "payload" object and the top-level tool
// arguments into a single payload map.
func mergeToolPayload(args map[string]any) map[string]any {
	payload := make(map[string]any)
	if nested, ok := args["payload"].(map[string]any); ok {
		for k, v := range nested {
			payload[k] = v
		}
	}
	for k, v := range args {
		if k != "payload" {
			payload[k] = v
		}
	}
	return payload
}

// clonePayload copies a payload map so session variants cannot bleed state
// into each other.
func clonePayload(payload map[string]any) map[string]any {
	iterPayload := make(map[string]any, len(payload))
	for k, v := range payload {
		iterPayload[k] = v
	}
	return iterPayload
}

// targetUsedFromPayload resolves the effective target of a payload, falling
// back to the engagement's initial target.
func targetUsedFromPayload(initialTarget string, payload map[string]any) string {
	if tStr, ok := payload["target"].(string); ok && strings.TrimSpace(tStr) != "" {
		return strings.TrimSpace(tStr)
	}
	if uStr, ok := payload["url"].(string); ok && strings.TrimSpace(uStr) != "" {
		return strings.TrimSpace(uStr)
	}
	if ipStr, ok := payload["ip"].(string); ok && strings.TrimSpace(ipStr) != "" {
		return strings.TrimSpace(ipStr)
	}
	return initialTarget
}

// allowlistedIPsSummary renders the allowlist for LLM-facing policy messages.
func allowlistedIPsSummary(allowlist map[string]bool) string {
	if len(allowlist) == 0 {
		return "none"
	}
	ips := make([]string, 0, len(allowlist))
	for ip := range allowlist {
		ips = append(ips, ip)
	}
	sortStrings(ips)
	return strings.Join(ips, ", ")
}

// isPayloadAllowedByIPWhitelist checks every host-ish field of a payload
// against the engagement's IP allowlist. An empty allowlist allows anything;
// a payload whose hosts cannot be resolved to any IP is rejected.
func isPayloadAllowedByIPWhitelist(payload map[string]any, allowlist map[string]bool) bool {
	if len(allowlist) == 0 {
		return true
	}
	collect := func(value any, out map[string]bool) {
		switch v := value.(type) {
		case string:
			parsed := strings.TrimSpace(v)
			if parsed == "" {
				return
			}
			if strings.Contains(parsed, "://") {
				if u, err := url.Parse(parsed); err == nil {
					parsed = u.Hostname()
				}
			}
			if ip := net.ParseIP(parsed); ip != nil {
				s := ip.String()
				if s != "0.0.0.0" && s != "::" {
					out[s] = true
				}
			} else {
				ips, err := net.LookupIP(parsed)
				if err == nil {
					for _, ip := range ips {
						s := ip.String()
						if s != "0.0.0.0" && s != "::" {
							out[s] = true
						}
					}
				}
			}
		}
	}

	ips := make(map[string]bool)
	collect(payload["ip"], ips)
	collect(payload["target"], ips)
	collect(payload["url"], ips)
	if nested, ok := payload["payload"].(map[string]any); ok {
		collect(nested["ip"], ips)
		collect(nested["target"], ips)
		collect(nested["url"], ips)
	}
	if len(ips) == 0 {
		return false
	}
	for ip := range ips {
		if !allowlist[ip] {
			return false
		}
	}
	return true
}

// requiresCredentialValidation reports whether a finding describes a
// credential leak that must not be marked exploitable without authentication
// evidence.
func requiresCredentialValidation(finding string) bool {
	lowerFinding := strings.ToLower(strings.TrimSpace(finding))
	if lowerFinding == "" {
		return false
	}
	if strings.Contains(lowerFinding, ".env") {
		return true
	}
	credentialLeakIndicators := []string{"credential", "password", "username", "token", "secret", "api key", "apikey", "session"}
	for _, indicator := range credentialLeakIndicators {
		if strings.Contains(lowerFinding, indicator) {
			if strings.Contains(lowerFinding, "leak") || strings.Contains(lowerFinding, "exposed") || strings.Contains(lowerFinding, "public") || strings.Contains(lowerFinding, "disclos") {
				return true
			}
		}
	}
	return false
}

// credentialUseEvidenceInTestCode reports whether test code shows a
// credential-based authentication attempt that succeeded.
func credentialUseEvidenceInTestCode(testCode string) bool {
	lowerTestCode := strings.ToLower(strings.TrimSpace(testCode))
	if lowerTestCode == "" {
		return false
	}
	hasCredentialAttempt := strings.Contains(lowerTestCode, "login") || strings.Contains(lowerTestCode, "auth") || strings.Contains(lowerTestCode, "credential") || strings.Contains(lowerTestCode, "username") || strings.Contains(lowerTestCode, "password") || strings.Contains(lowerTestCode, "session")
	hasSuccessEvidence := strings.Contains(lowerTestCode, "authenticated") || strings.Contains(lowerTestCode, "logged in") || strings.Contains(lowerTestCode, "success") || strings.Contains(lowerTestCode, "valid") || strings.Contains(lowerTestCode, "200") || strings.Contains(lowerTestCode, "token issued")
	return hasCredentialAttempt && hasSuccessEvidence
}

// validateVulnerabilityLogInput enforces the log_vulnerability parameter
// contract, including the confirmed/informational severity pairing and the
// credential-leak exploitable evidence rule.
func validateVulnerabilityLogInput(vulnID string, target string, finding string, testCode string, exploitable string, status string, severity string) error {
	if strings.TrimSpace(vulnID) == "" || strings.TrimSpace(target) == "" || strings.TrimSpace(finding) == "" || strings.TrimSpace(testCode) == "" || (exploitable != "yes" && exploitable != "no") {
		return fmt.Errorf("vuln_id, target, finding, test_code, and exploitable ('yes'|'no') are required")
	}
	if status != matrix.VulnerabilityStatusConfirmed && status != matrix.VulnerabilityStatusInformational {
		return fmt.Errorf("status must be 'confirmed' or 'informational'")
	}
	if !matrix.IsValidVulnerabilitySeverity(severity) {
		return fmt.Errorf("severity must be one of critical, high, medium, low, informational, or unknown")
	}
	if status == matrix.VulnerabilityStatusInformational && exploitable == "yes" {
		return fmt.Errorf("informational findings cannot be marked exploitable='yes'")
	}
	if status == matrix.VulnerabilityStatusInformational && severity != matrix.VulnerabilitySeverityInformational {
		return fmt.Errorf("informational findings must use severity='informational'")
	}
	if status == matrix.VulnerabilityStatusConfirmed && severity == matrix.VulnerabilitySeverityInformational {
		return fmt.Errorf("confirmed vulnerabilities cannot use severity='informational'")
	}
	if exploitable == "yes" && requiresCredentialValidation(finding) && !credentialUseEvidenceInTestCode(testCode) {
		return fmt.Errorf("credential leaks cannot be marked exploitable='yes' without evidence of a successful credential-based authentication attempt in test_code")
	}
	return nil
}
