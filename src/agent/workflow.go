package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"charm.land/fantasy"
	"charm.land/fantasy/providers/anthropic"
	"charm.land/fantasy/providers/google"
	"charm.land/fantasy/providers/openai"
	"github.com/charmbracelet/log"

	"fire_starter/src/matrix"
	core "fire_starter/src/modules/core"
)

func initializeModel(ctx context.Context, cfg Config) (fantasy.LanguageModel, error) {
	var provider fantasy.Provider
	var err error

	switch strings.ToLower(cfg.Provider) {
	case "openai", "local", "ollama":
		var opts []openai.Option
		if cfg.BaseURL != "" {
			opts = append(opts, openai.WithBaseURL(normalizeBaseURL(cfg.Provider, cfg.BaseURL)))
		}
		provider, err = openai.New(opts...)
	case "anthropic":
		provider, err = anthropic.New()
	case "gemini", "google":
		provider, err = google.New()
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to init provider %s: %w", cfg.Provider, err)
	}

	return provider.LanguageModel(ctx, cfg.Model)
}

func generateWithRetry(ctx context.Context, model fantasy.LanguageModel, call fantasy.Call, maxRetries int) (*fantasy.Response, error) {
	var resp *fantasy.Response
	var err error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err = model.Generate(ctx, call)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt < maxRetries {
			errLower := strings.ToLower(err.Error())
			isRateLimit := strings.Contains(errLower, "429") || strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "quota") || strings.Contains(errLower, "resource_exhausted")
			maxWait := 6 * time.Second
			if isRateLimit {
				maxWait = 30 * time.Second
				if backoff < 2*time.Second {
					backoff = 2 * time.Second
				}
			}
			log.Warnf("LLM generation error (attempt %d/%d): %v. Retrying in %v...", attempt+1, maxRetries, err, backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxWait {
					backoff = maxWait
				}
			}
		}
	}
	return nil, err
}

func normalizeBaseURL(provider string, baseURL string) string {
	if baseURL == "" {
		return ""
	}

	trimmed := strings.TrimRight(baseURL, "/")
	switch strings.ToLower(provider) {
	case "local", "ollama":
		if strings.HasSuffix(trimmed, "/v1") {
			return trimmed
		}
		return trimmed + "/v1"
	default:
		return baseURL
	}
}

// loadDecisions reads and parses the technique catalog backing the executor.
func loadDecisions() ([]matrix.Decision, error) {
	decisionsFile := "src/matrix/decisions.json"
	bytes, err := matrix.ReadDecisionsFile(decisionsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read decisions.json: %w", err)
	}

	var data matrix.DecisionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("error parsing decisions JSON: %w", err)
	}
	return data.Decisions, nil
}

// newAgentEnv builds the shared run environment: the technique catalog, the
// module executor, the knowledge graph (with persisted target state restored),
// and the engagement scope. On success the caller owns closing env.kg.
func newAgentEnv(target string, cfg Config, onKGUpdate func(*matrix.KnowledgeGraph)) (*agentEnv, error) {
	decisions, err := loadDecisions()
	if err != nil {
		return nil, err
	}
	executor, err := matrix.NewRealExecutor(decisions)
	if err != nil {
		return nil, fmt.Errorf("failed to init executor: %w", err)
	}
	executor.SetOOBPublicHost(cfg.OOBPublicHost)

	// Catalog drift check: decisions.json entries and registered technique
	// modules must match 1:1 in both directions, otherwise the agent would
	// either advertise tools it cannot run or never run registered modules.
	declared := executor.RegisteredTechniques()
	registered := core.RegisteredModuleTechniques()
	for _, m := range registered {
		if !declared[m] {
			return nil, fmt.Errorf("catalog drift: module %q registered but no decisions.json entry", m)
		}
	}
	for m := range declared {
		if _, ok := core.GetModuleFactory(m); !ok {
			return nil, fmt.Errorf("catalog drift: decision %q has no registered module", m)
		}
	}
	for _, d := range decisions {
		if !matrix.IsValidPhase(d.Phase) {
			return nil, fmt.Errorf("catalog drift: decision %q has invalid phase %q", d.Identifier, d.Phase)
		}
	}

	kg := matrix.NewKnowledgeGraph()
	kg.ConfigTarget = target
	// Install the update callback BEFORE restoring persisted state or seeding
	// scope so observers (TUI) see the initial population too.
	kg.SetOnUpdate(onKGUpdate)

	env := &agentEnv{
		cfg:             cfg,
		kg:              kg,
		executor:        executor,
		decisions:       decisions,
		initialTarget:   target,
		allowlist:       make(map[string]bool),
		toolStageByName: make(map[string]matrix.Phase),
		globalIters:     new(int),
		payloadHashes:   make(map[string]bool),
	}
	for _, t := range executor.Tools() {
		env.toolStageByName[t.Name] = matrix.Phase(t.Phase)
	}

	restorePersistedTargets(env)
	configureTargetScope(env)
	return env, nil
}

// restorePersistedTargets reloads previously recorded target state from
// SQLite into the knowledge graph. Persistence is best-effort: failures are
// logged and the run continues with an empty graph.
func restorePersistedTargets(env *agentEnv) {
	if _, err := matrix.InitDB("fire_starter.db"); err != nil {
		log.Warnf("Failed to init SQLite database: %v", err)
		return
	}
	storedStates, err := matrix.LoadTargetStates()
	if err != nil || len(storedStates) == 0 {
		return
	}
	for _, st := range storedStates {
		if st.Type == "ip" {
			env.kg.AddIP(st.TargetDomain)
		} else {
			env.kg.AddURL(st.TargetDomain, st.TargetDomain)
		}
		for _, port := range st.OpenPorts {
			env.kg.AddPort(st.TargetDomain, port)
		}
		for _, tok := range st.Tokens {
			env.kg.AddToken(st.TargetDomain, "default", tok)
		}
		if st.CurrentPhase != "" {
			env.kg.SetTargetPhase(st.TargetDomain, matrix.Phase(st.CurrentPhase))
		}
	}
	log.Infof("Restored %d target state(s) from persistent storage.", len(storedStates))
}

// buildAllowlist seeds the IP allowlist from the configured whitelist entries,
// registering each entry in the knowledge graph.
func buildAllowlist(env *agentEnv) map[string]bool {
	allowlist := make(map[string]bool)
	for _, ip := range env.cfg.IPWhitelist {
		trimmed := strings.TrimSpace(ip)
		if parsed := net.ParseIP(trimmed); parsed != nil {
			allowlist[parsed.String()] = true
			env.kg.AddAllowedIP(parsed.String())
			env.kg.AddIP(parsed.String())
		}
	}
	return allowlist
}

// registerInitialTarget registers the configured engagement target in the
// knowledge graph as URL or IP and allowlists its resolved addresses.
func registerInitialTarget(kg *matrix.KnowledgeGraph, target string) {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			if ips, err := net.LookupIP(u.Hostname()); err == nil {
				for _, ip := range ips {
					kg.AddAllowedIP(ip.String())
				}
			}
		}
		kg.AddURL(target, target)
		return
	}
	if net.ParseIP(target) != nil {
		kg.AddAllowedIP(target)
		kg.AddIP(target)
		return
	}
	if ips, err := net.LookupIP(target); err == nil {
		for _, ip := range ips {
			kg.AddAllowedIP(ip.String())
		}
	}
	kg.AddURL("http://"+target, "http://"+target)
}

// configureTargetScope seeds the knowledge graph with the engagement scope:
// target domains, the IP allowlist (kept empty when only the initial target
// is in scope), the configured credentials, and the context values.
func configureTargetScope(env *agentEnv) {
	kg := env.kg
	target := env.initialTarget
	cfg := env.cfg

	// Populate TargetDomains whitelist from config
	if len(cfg.TargetDomains) > 0 {
		kg.TargetDomains = cfg.TargetDomains
	} else {
		kg.TargetDomains = deriveDefaultTargetDomains(target)
	}

	// For backwards compatibility, set BaseDomain to the first target domain
	if len(kg.TargetDomains) > 0 {
		first := kg.TargetDomains[0]
		if strings.HasPrefix(first, "*.") {
			kg.BaseDomain = first[2:]
		} else {
			kg.BaseDomain = first
		}
	}

	allowlist := buildAllowlist(env)
	for _, ip := range extractIPsFromTarget(target) {
		if len(allowlist) == 0 || allowlist[ip] {
			kg.AddAllowedIP(ip)
			kg.AddIP(ip)
		}
	}
	registerInitialTarget(kg, target)
	for _, cred := range cfg.Credentials {
		if strings.TrimSpace(cred.Username) == "" {
			continue
		}
		kg.AddCredential(target, strings.TrimSpace(cred.Username), cred.Password)
	}
	kg.SetContextValue("ip_whitelist", cfg.IPWhitelist)
	kg.SetContextValue("rules_of_engagement", cfg.RulesOfEngagement)
	env.allowlist = allowlist
}

// extractIPsFromTarget resolves a target string (URL, IP literal, or host) to
// its routable IP addresses, excluding unspecified addresses.
func extractIPsFromTarget(target string) []string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil
	}
	parsed := strings.TrimSpace(trimmed)
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			parsed = u.Hostname()
		}
	}
	if ip := net.ParseIP(parsed); ip != nil {
		if ip.String() == "0.0.0.0" || ip.String() == "::" {
			return nil
		}
		return []string{ip.String()}
	}
	ips, err := net.LookupIP(parsed)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if s == "0.0.0.0" || s == "::" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// deriveDefaultTargetDomains derives the scoped domain set from the initial
// target when the configuration specifies no explicit target domains.
func deriveDefaultTargetDomains(target string) []string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil
	}

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return nil
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return nil
	}
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return []string{host}
	}

	return []string{host, "*." + host}
}

// runOrchestrationLoop schedules the target agent loop over every pending
// target the knowledge graph discovers, until the iteration budget is spent.
func runOrchestrationLoop(ctx context.Context, env *agentEnv) {
	processedTargets := make(map[string]bool)

	for {
		if reachedIterationLimit(*env.globalIters, env.cfg.MaxIters) {
			log.Warnf("Global run loop reached MaxIters (%d). Stopping target scheduling.", env.cfg.MaxIters)
			break
		}

		pendingTargets := env.kg.GetPendingTargets(processedTargets)

		if len(pendingTargets) == 0 {
			break
		}

		for _, tVal := range pendingTargets {
			if reachedIterationLimit(*env.globalIters, env.cfg.MaxIters) {
				log.Warnf("Global run loop reached MaxIters (%d). Skipping remaining pending targets.", env.cfg.MaxIters)
				break
			}
			processedTargets[tVal] = true
			log.Infof("Starting agent loop for target: %s", tVal)
			if err := runTargetAgent(ctx, env, tVal); err != nil {
				log.Errorf("Target agent for %s failed: %v", tVal, err)
			}
		}
	}
}

// buildGlobalHelperTools assembles the toolset for post-loop helper runs:
// every registered technique tool plus the query and vulnerability logging
// control tools.
func buildGlobalHelperTools(env *agentEnv) []fantasy.Tool {
	var activeTools []fantasy.Tool
	for _, t := range env.executor.Tools() {
		activeTools = append(activeTools, fantasy.FunctionTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	activeTools = append(activeTools, queryKnowledgeGraphTool())
	activeTools = append(activeTools, logVulnerabilityTool())
	return activeTools
}

// runPostLoopHelpers validates any candidate findings that are still
// unresolved after the orchestration loop, one helper sub-agent per finding.
func runPostLoopHelpers(ctx context.Context, env *agentEnv) {
	if reachedIterationLimit(*env.globalIters, env.cfg.MaxIters) {
		log.Warnf("Skipping post-loop vulnerability helper processing because MaxIters (%d) was reached.", env.cfg.MaxIters)
		return
	}

	preVulns, preErr := matrix.GetVulnerabilities()
	if preErr != nil {
		return
	}

	activeTools := buildGlobalHelperTools(env)
	for _, v := range preVulns {
		if v.Status == matrix.VulnerabilityStatusCandidate {
			log.Infof("Processing remaining candidate finding: target=%s vuln_id=%s finding=%q", v.TargetDomain, v.VulnID, v.Finding)
			_ = runVulnerabilityHelperSubAgent(ctx, env, v.TargetDomain, v.Finding, v.VulnID, activeTools)
		}
	}
}

// RunAgent executes the full autonomous assessment: it initializes the model,
// builds the shared run environment, drives the target orchestration loop,
// validates remaining candidate findings with helper sub-agents, and writes
// the final report.
func RunAgent(ctx context.Context, target string, cfg Config, onKGUpdate func(*matrix.KnowledgeGraph)) (string, error) {
	// Apply the TLS opt-in before any module can issue requests.
	core.SetTransportInsecureSkipVerify(cfg.TLSSkipVerify)

	model, err := initializeModel(ctx, cfg)
	if err != nil {
		return "", err
	}

	env, err := newAgentEnv(target, cfg, onKGUpdate)
	if err != nil {
		return "", err
	}
	defer env.kg.Close()
	env.model = model

	runOrchestrationLoop(ctx, env)
	runPostLoopHelpers(ctx, env)

	return generateFinalReport(ctx, env), nil
}
