package main

import (
	"fmt"
	"sort"
	"strings"

	"blackwater/decisiontree"
)

func formatResultBlock(result decisiontree.ToolResult, stage string) string {
	calls := make([]string, 0, len(result.Calls))
	for _, c := range result.Calls {
		calls = append(calls, fmt.Sprintf("- %s.%s: %s", c.Tool, c.Function, c.Purpose))
	}
	if len(calls) == 0 {
		calls = append(calls, "- none")
	}

	keys := make([]string, 0, len(result.Output))
	for k := range result.Output {
		if k == "next_payload" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	outputParts := make([]string, 0, len(keys))
	for _, k := range keys {
		outputParts = append(outputParts, fmt.Sprintf("%s=%v", k, result.Output[k]))
	}
	if len(outputParts) == 0 {
		outputParts = append(outputParts, "none")
	}

	return strings.Join([]string{
		fmt.Sprintf("Stage %s completed", stage),
		"Calls:",
		strings.Join(calls, "\n"),
		"Output:",
		strings.Join(outputParts, ", "),
	}, "\n")
}

func buildInitialInput(ip string, port string) decisiontree.ThirdPartyInput {
	payload := map[string]any{
		"ip":      ip,
		"has_api": true,
	}
	if port != "" {
		payload["port"] = port
	}
	return decisiontree.ThirdPartyInput{Stage: stageTargetReceived, Payload: payload}
}

func buildInputForStage(current decisiontree.ThirdPartyInput, stage string, ip string, port string) decisiontree.ThirdPartyInput {
	payload := copyMap(current.Payload)
	if ip != "" {
		payload["ip"] = ip
	}
	if port != "" {
		payload["port"] = port
	}
	target := formatTarget(ip, port)
	switch {
	case strings.HasPrefix(stage, "application-mapping."), strings.HasPrefix(stage, "active-testing."):
		payload["target"] = target
	case strings.HasPrefix(stage, "api-testing."):
		payload["ip"] = ip
		payload["has_api"] = true
	}
	return decisiontree.ThirdPartyInput{Stage: stage, Payload: payload}
}

func moduleFromStage(stage string) string {
	switch {
	case strings.HasPrefix(stage, "target."):
		return "Target Intake"
	case strings.HasPrefix(stage, "api-testing."):
		return "API Testing"
	case strings.HasPrefix(stage, "application-mapping."):
		return "Application Mapping"
	case strings.HasPrefix(stage, "active-testing."):
		return "Active Testing"
	default:
		return "Unknown"
	}
}

func availableModules() []moduleOption {
	return []moduleOption{
		{name: "API Testing", startStage: stageAPITestingRecon},
		{name: "Application Mapping", startStage: stageApplicationMappingExplore},
		{name: "Active Testing", startStage: stageActiveTestingAccessControl},
	}
}

func copyMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func onOff(v bool) string {
	if v {
		return "ON"
	}
	return "OFF"
}

func emptyFallback(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func formatTarget(ip string, port string) string {
	if ip == "" {
		return "-"
	}
	if port == "" {
		return "http://" + ip
	}
	return "http://" + ip + ":" + port
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
