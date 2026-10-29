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
	registry          *ToolRegistry
	toolByName        map[string]ToolDefinition
	sessionAwareTools map[string]bool
	oobPublicHost     string
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
func NewRealExecutor(decisions []Decision) (*RealExecutor, error) {
	registry := NewToolRegistry(decisions)
	toolByName := make(map[string]ToolDefinition, len(decisions))
	sessionAwareTools := make(map[string]bool, len(decisions))
	dummyPayload := map[string]any{"target": "http://127.0.0.1", "url": "http://127.0.0.1", "ip": "127.0.0.1"}

	for _, tool := range registry.ListTools() {
		toolByName[tool.Name] = tool
		technique := strings.ToLower(strings.TrimSpace(tool.Technique))

		// Reconnaissance tools should never be treated as session aware
		if technique == "port_scanning" || technique == "google_dorking" ||
			technique == "subdomain_enumeration" || technique == "subdomain_takeover_analysis" {
			sessionAwareTools[tool.Name] = false
			continue
		}

		if factory, ok := modules.GetModuleFactory(technique); ok {
			if mod, err := factory(dummyPayload, func(string) {}); err == nil && mod != nil {
				underlying := mod.GetUnderlying()
				if _, ok := underlying.(modules.SessionAware); ok {
					sessionAwareTools[tool.Name] = true
				} else if _, ok := underlying.(interface{ GetBaseModule() *modules.BaseModule }); ok {
					sessionAwareTools[tool.Name] = true
				}
			}
		}
	}
	return &RealExecutor{registry: registry, toolByName: toolByName, sessionAwareTools: sessionAwareTools}, nil
}

func (e *RealExecutor) IsSessionAware(toolName string) bool {
	if e == nil || e.sessionAwareTools == nil {
		return false
	}
	return e.sessionAwareTools[toolName]
}

func (e *RealExecutor) Tools() []ToolDefinition {
	return e.registry.ListTools()
}

// SetOOBPublicHost configures the externally reachable out-of-band callback
// host that is injected into module payloads as "oob_host" before factory
// lookup. An empty value (the default) keeps the loopback-safe OOB behavior.
func (e *RealExecutor) SetOOBPublicHost(host string) {
	e.oobPublicHost = strings.TrimSpace(host)
}

func (e *RealExecutor) ExecuteByToolName(ctx context.Context, toolName string, payload map[string]any, onLog func(string)) (string, error) {
	tool, ok := e.toolByName[toolName]
	if !ok {
		return "", fmt.Errorf("tool %s not found", toolName)
	}
	if e.oobPublicHost != "" {
		if payload == nil {
			payload = make(map[string]any)
		}
		if _, ok := payload["oob_host"]; !ok {
			payload["oob_host"] = e.oobPublicHost
		}
	}
	decision := Decision{Identifier: tool.Identifier, Technique: tool.Technique, Phase: tool.Phase}
	return e.executeDecision(ctx, decision, payload, onLog)
}

func (e *RealExecutor) executeDecision(ctx context.Context, decision Decision, payload map[string]any, onLog func(string)) (string, error) {
	stage := decisionPhase(decision.Phase)
	onLog(fmt.Sprintf("Mapped decision technique '%s' to node stage '%s'", decision.Technique, stage))

	if payload == nil {
		payload = make(map[string]any)
	}

	targetStr := payloadString(payload, "target", "")
	ipStr := payloadString(payload, "ip", "")
	urlStr := payloadString(payload, "url", "")
	if urlStr == "" && targetStr != "" {
		urlStr = targetStr
	}
	if urlStr != "" {
		urlStr = modules.EnsureHTTPPrefix(urlStr)
		payload["url"] = urlStr
	}
	cookiesStr := payloadString(payload, "cookies", "")

	if ipStr == "" && urlStr == "" {
		return "", fmt.Errorf(`{"error":"payload missing target url/ip"}`)
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
			if sa, ok := module.(modules.SessionAware); ok {
				sa.SetCookies(cookiesStr)
			} else if hasBaseModule, ok := module.(interface{ GetBaseModule() *modules.BaseModule }); ok {
				hasBaseModule.GetBaseModule().SetCookies(cookiesStr)
			}
		}
	}

	technique := strings.ToLower(strings.TrimSpace(decision.Technique))

	factory, ok := modules.GetModuleFactory(technique)
	if !ok {
		return fmt.Sprintf(`{"error":"unknown technique %s"}`, technique), fmt.Errorf("unknown technique %s", technique)
	} else {
		module, err := factory(payload, onLog)
		if err != nil {
			return "", fmt.Errorf("failed to create module %s: %v", technique, err)
		}

		injectCookies(module.GetUnderlying())

		// Configure thread concurrency if specified in payload and module supports it
		if threadsVal, ok := payload["threads"]; ok {
			var threads int
			switch v := threadsVal.(type) {
			case int:
				threads = v
			case float64:
				threads = int(v)
			case string:
				threads, _ = strconv.Atoi(v)
			}
			if threads > 0 {
				if tc, ok := module.GetUnderlying().(modules.ThreadConfigurable); ok {
					tc.SetThreads(threads)
				} else if hasBaseModule, ok := module.GetUnderlying().(interface{ GetBaseModule() *modules.BaseModule }); ok {
					base := hasBaseModule.GetBaseModule()
					if base != nil {
						base.SetThreads(threads)
					}
				}
			}
		}

		results, err := module.Execute(ctx)
		if err != nil {
			return fmt.Sprintf("%s failed: %v", technique, err), err
		}
		resultOutput[technique+"_results"] = results

		if pp, ok := module.GetUnderlying().(modules.PoCProvider); ok {
			pocs := pp.GetPoCs()
			if len(pocs) > 0 {
				resultOutput["reproduction_steps"] = pocs
			}
		} else if hasBaseModule, ok := module.GetUnderlying().(interface{ GetBaseModule() *modules.BaseModule }); ok {
			base := hasBaseModule.GetBaseModule()
			if base != nil {
				pocs := base.GetPoCs()
				if len(pocs) > 0 {
					resultOutput["reproduction_steps"] = pocs
				}
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

// decisionPhase resolves the engagement phase for a decision from its
// declared phase, falling back to reconnaissance for unknown or empty values.
func decisionPhase(phase string) string {
	switch Phase(phase) {
	case PhasePreEngagement, PhaseReconnaissance, PhaseScanning, PhaseVulnerabilityAnalysis,
		PhaseExploitation, PhasePostExploitation, PhaseReporting:
		return phase
	default:
		return string(PhaseReconnaissance)
	}
}

// RegisteredTechniques returns the set of technique names this executor can
// actually run (as declared in its decisions, matching modules registered in
// src/modules/core). Callers use it to detect catalog drift between
// decisions.json entries and RegisterModule'd modules in both directions:
//
//	registered := modules.RegisteredModuleTechniques()
//	declared := executor.RegisteredTechniques()
//	for _, m := range registered {
//	    if !declared[m] { ... decision missing for registered module ... }
//	}
//	for m := range declared {
//	    if _, ok := modules.GetModuleFactory(m); !ok { ... module missing for decision ... }
//	}
func (e *RealExecutor) RegisteredTechniques() map[string]bool {
	out := make(map[string]bool, len(e.toolByName))
	for _, tool := range e.toolByName {
		out[strings.ToLower(strings.TrimSpace(tool.Technique))] = true
	}
	return out
}
