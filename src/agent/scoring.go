package agent

import (
	"fmt"
	"sort"
	"strings"

	"fire_starter/src/matrix"
)

type scoredTool struct {
	Definition matrix.ToolDefinition
	Score      int
	Reasons    []string
}

// httpRequestGateState tracks whether decision_http_request has run against a
// target and the fingerprints of the target/auth state it last ran against,
// so the tool is only re-offered when new intelligence arrives.
type httpRequestGateState struct {
	hasExecuted           bool
	lastTargetFingerprint string
	lastAuthFingerprint   string
}

func normalizeTarget(t string) string {
	return matrix.NormalizeURL(t)
}

func joinSortedStrings(values []string) string {
	if len(values) == 0 {
		return ""
	}

	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return strings.Join(copyValues, ",")
}

func joinSortedInts(values []int) string {
	if len(values) == 0 {
		return ""
	}

	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	parts := make([]string, 0, len(copyValues))
	for _, value := range copyValues {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func sortStrings(values []string) {
	sort.Strings(values)
}

func credentialSignalFingerprint(credentials []matrix.CredentialInfo) string {
	if len(credentials) == 0 {
		return ""
	}

	signals := make(map[string]bool)
	for _, credential := range credentials {
		username := strings.ToLower(strings.TrimSpace(credential.Username))
		if username == "" {
			username = "<blank>"
		}
		signals[username] = true
	}

	parts := make([]string, 0, len(signals))
	for signal := range signals {
		parts = append(parts, signal)
	}
	return joinSortedStrings(parts)
}

func tokenSignalFingerprint(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}

	signals := make(map[string]bool)
	for _, token := range tokens {
		trimmed := strings.TrimSpace(token)
		if trimmed == "" {
			continue
		}
		if name, _, ok := strings.Cut(trimmed, "="); ok {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				signals["cookie:"+name] = true
				continue
			}
		}

		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "bearer "):
			signals["bearer"] = true
		case strings.Count(trimmed, ".") == 2:
			signals["jwt"] = true
		default:
			signals["opaque"] = true
		}
	}

	parts := make([]string, 0, len(signals))
	for signal := range signals {
		parts = append(parts, signal)
	}
	return joinSortedStrings(parts)
}

func httpRequestTargetFingerprint(target *matrix.Target) string {
	if target == nil {
		return ""
	}

	return fmt.Sprintf(
		"target=%s|phase=%s|ports=%s|vulns=%s",
		normalizeTarget(target.Value),
		target.CurrentPhase,
		joinSortedInts(target.OpenPorts),
		joinSortedStrings(target.Vulnerabilities),
	)
}

func httpRequestAuthFingerprint(target *matrix.Target) string {
	if target == nil {
		return ""
	}

	return fmt.Sprintf(
		"token_signals=%s|credential_signals=%s",
		tokenSignalFingerprint(target.Tokens),
		credentialSignalFingerprint(target.Credentials),
	)
}

func authReopenGateKey(targetFingerprint string, authFingerprint string) string {
	return targetFingerprint + "|" + authFingerprint
}

func updateHTTPRequestGateState(state *httpRequestGateState, target *matrix.Target) {
	if state == nil || target == nil {
		return
	}

	state.hasExecuted = true
	state.lastTargetFingerprint = httpRequestTargetFingerprint(target)
	state.lastAuthFingerprint = httpRequestAuthFingerprint(target)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasPort(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}

func scoreTool(def matrix.ToolDefinition, target *matrix.Target, snapshot matrix.KnowledgeSnapshot, httpRequestState *httpRequestGateState) scoredTool {
	stage := matrix.Phase(def.Phase)
	score := 0
	reasons := make([]string, 0, 4)

	for _, exec := range target.ExecutedTools {
		if exec == def.Name {
			if def.Name != "decision_http_request" {
				return scoredTool{Definition: def, Score: -100, Reasons: []string{"already executed on this target"}}
			}
		}
	}

	if def.Name == "decision_http_request" {
		targetFingerprint := httpRequestTargetFingerprint(target)
		authFingerprint := httpRequestAuthFingerprint(target)
		switch {
		case httpRequestState == nil || !httpRequestState.hasExecuted:
			score += 50
			reasons = append(reasons, "http_request allowed for initial target probe")
		case targetFingerprint != httpRequestState.lastTargetFingerprint:
			score += 35
			reasons = append(reasons, "target intelligence unlocked another http_request")
		case authFingerprint != httpRequestState.lastAuthFingerprint:
			gateKey := authReopenGateKey(targetFingerprint, authFingerprint)
			if target.HTTPRequestGate != nil && target.HTTPRequestGate[gateKey] {
				return scoredTool{Definition: def, Score: -100, Reasons: []string{"authenticated follow-up already used for this target state"}}
			}
			score += 20
			reasons = append(reasons, "one authenticated follow-up allowed for the current target state")
		default:
			return scoredTool{Definition: def, Score: -100, Reasons: []string{"no new target intelligence since last http_request"}}
		}
	}

	switch {
	case stage == target.CurrentPhase:
		score += 10
		reasons = append(reasons, "matches target phase")
	case stage == matrix.PhaseReconnaissance:
		score += 3
		reasons = append(reasons, "always-recon exception")
	}

	name := strings.ToLower(def.Name)
	if strings.Contains(name, "ssh") && hasPort(target.OpenPorts, 22) {
		score += 3
		reasons = append(reasons, "ssh port 22 is open")
	}
	hasWebPort := hasPort(target.OpenPorts, 80) || hasPort(target.OpenPorts, 443) || hasPort(target.OpenPorts, 8080) || hasPort(target.OpenPorts, 8443) || strings.HasPrefix(target.Value, "http://") || strings.HasPrefix(target.Value, "https://")
	if (strings.Contains(name, "sql") || strings.Contains(name, "database") || strings.Contains(name, "db")) && (hasWebPort || hasPort(target.OpenPorts, 3306) || hasPort(target.OpenPorts, 5432)) {
		score += 3
		reasons = append(reasons, "database or web interface is available")
	}
	if strings.Contains(name, "ftp") && hasPort(target.OpenPorts, 21) {
		score += 3
		reasons = append(reasons, "ftp port 21 is open")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "baseline")
	}

	return scoredTool{Definition: def, Score: score, Reasons: reasons}
}

func canCompleteTarget(snapshot matrix.KnowledgeSnapshot, target string, efficiencyMode bool) (bool, string) {
	phase, ok := snapshot.TargetPhases[target]
	if !ok {
		return false, "target not found in snapshot"
	}

	if phase == matrix.PhaseReporting {
		return true, "target exhausted"
	}

	if efficiencyMode {
		return true, "efficiency mode enabled, target can be skipped or exited early"
	}

	if snapshot.VulnerabilityCount == 0 {
		if phase != matrix.PhaseReconnaissance {
			return true, "no vulnerabilities found and target completed recon, early exit allowed"
		}
		return false, "no vulnerabilities found, but target must complete recon before early exit"
	}

	return false, "vulnerabilities found globally; must exhaust target before completing"
}

func summarizeSnapshot(snapshot matrix.KnowledgeSnapshot) string {
	return fmt.Sprintf("ips=%d urls=%d open_ports=%d vulnerabilities=%d tokens=%d targets=%d",
		snapshot.DiscoveredIPCount,
		snapshot.DiscoveredURLCount,
		snapshot.OpenPortCount,
		snapshot.VulnerabilityCount,
		snapshot.HarvestedTokenCount,
		len(snapshot.TargetPhases),
	)
}

func reachedIterationLimit(globalIters int, maxIters int) bool {
	return maxIters > 0 && globalIters >= maxIters
}

func snapshotDelta(before, after matrix.KnowledgeSnapshot) string {
	changes := make([]string, 0, 5)
	if after.DiscoveredIPCount > before.DiscoveredIPCount {
		changes = append(changes, fmt.Sprintf("ips:+%d", after.DiscoveredIPCount-before.DiscoveredIPCount))
	}
	if after.DiscoveredURLCount > before.DiscoveredURLCount {
		changes = append(changes, fmt.Sprintf("urls:+%d", after.DiscoveredURLCount-before.DiscoveredURLCount))
	}
	if after.OpenPortCount > before.OpenPortCount {
		changes = append(changes, fmt.Sprintf("open_ports:+%d", after.OpenPortCount-before.OpenPortCount))
	}
	if after.VulnerabilityCount > before.VulnerabilityCount {
		changes = append(changes, fmt.Sprintf("vulnerabilities:+%d", after.VulnerabilityCount-before.VulnerabilityCount))
	}
	if after.HarvestedTokenCount > before.HarvestedTokenCount {
		changes = append(changes, fmt.Sprintf("tokens:+%d", after.HarvestedTokenCount-before.HarvestedTokenCount))
	}
	if len(changes) == 0 {
		return "no_new_intelligence"
	}
	return strings.Join(changes, ",")
}

// applyHTTPRequestGate updates the decision_http_request bookkeeping after a
// successful execution: when an authenticated follow-up ran against an
// unchanged target fingerprint, its gate key is burned so it cannot be reused
// for the same target state.
func applyHTTPRequestGate(env *agentEnv) {
	state := env.httpRequestState
	if state == nil {
		return
	}
	env.kg.MutateTarget(env.currentTarget, func(targetObj *matrix.Target) {
		if targetObj.HTTPRequestGate == nil {
			targetObj.HTTPRequestGate = make(map[string]bool)
		}
		targetFingerprint := httpRequestTargetFingerprint(targetObj)
		authFingerprint := httpRequestAuthFingerprint(targetObj)
		if state.hasExecuted && authFingerprint != state.lastAuthFingerprint && targetFingerprint == state.lastTargetFingerprint {
			targetObj.HTTPRequestGate[authReopenGateKey(targetFingerprint, authFingerprint)] = true
		}
		updateHTTPRequestGateState(state, targetObj)
	})
}
