// File overview:
// Decision candidate generation and parsing helpers. It exists to produce resilient next-step options even when LLM output is missing or malformed.

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"blackwater/decisiontree"
)

func fallbackDecisions(input decisiontree.ThirdPartyInput, next decisiontree.ThirdPartyInput, continueFlow bool) []decisionItem {
	items := make([]decisionItem, 0, 3)
	if continueFlow && next.Stage != "" {
		items = append(items, decisionItem{
			title:     "Continue planned flow",
			desc:      fmt.Sprintf("Proceed to %s", next.Stage),
			nextStage: next.Stage,
		})
	} else {
		items = append(items, decisionItem{
			title:     "Stop and finalize",
			desc:      "End run and keep current findings.",
			nextStage: stopDecisionStage,
		})
	}

	currentModule := moduleFromStage(input.Stage)
	for _, module := range availableModules() {
		if len(items) == 3 {
			break
		}
		if module.name == currentModule {
			continue
		}
		if hasDecisionForStage(items, module.startStage) {
			continue
		}
		items = append(items, decisionItem{
			title:     "Switch to " + module.name,
			desc:      fmt.Sprintf("Start module at %s", module.startStage),
			nextStage: module.startStage,
		})
	}

	if len(items) < 3 {
		items = append(items, decisionItem{
			title:     "Stop and finalize",
			desc:      "End run and keep current findings.",
			nextStage: stopDecisionStage,
		})
	}
	for len(items) < 3 {
		items = append(items, items[len(items)-1])
	}
	return items[:3]
}

func parseLLMDecisions(raw string) []decisionItem {
	type llmDecision struct {
		Title     string `json:"title"`
		Reason    string `json:"reason"`
		NextStage string `json:"next_stage"`
	}

	jsonBlob := extractJSONArray(raw)
	if jsonBlob == "" {
		return nil
	}

	var decisions []llmDecision
	if err := json.Unmarshal([]byte(jsonBlob), &decisions); err != nil {
		return nil
	}
	if len(decisions) == 0 {
		return nil
	}

	allowed := allowedDecisionSet()
	items := make([]decisionItem, 0, 3)
	for _, d := range decisions {
		next := strings.TrimSpace(d.NextStage)
		if _, ok := allowed[next]; !ok {
			continue
		}
		title := strings.TrimSpace(d.Title)
		reason := strings.TrimSpace(d.Reason)
		if title == "" {
			title = "Decision"
		}
		if reason == "" {
			reason = fmt.Sprintf("Proceed to %s", next)
		}
		items = append(items, decisionItem{title: title, desc: reason, nextStage: next})
		if len(items) == 3 {
			break
		}
	}
	return items
}

func mergeWithFallback(primary []decisionItem, fallback []decisionItem) []decisionItem {
	merged := make([]decisionItem, 0, 3)
	seen := map[string]struct{}{}
	for _, item := range primary {
		if _, ok := seen[item.nextStage]; ok {
			continue
		}
		merged = append(merged, item)
		seen[item.nextStage] = struct{}{}
		if len(merged) == 3 {
			return merged
		}
	}
	for _, item := range fallback {
		if _, ok := seen[item.nextStage]; ok {
			continue
		}
		merged = append(merged, item)
		seen[item.nextStage] = struct{}{}
		if len(merged) == 3 {
			return merged
		}
	}
	for len(merged) < 3 {
		merged = append(merged, decisionItem{title: "Stop and finalize", desc: "End run and keep current findings.", nextStage: stopDecisionStage})
	}
	return merged
}

func extractJSONArray(raw string) string {
	raw = strings.TrimSpace(raw)
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return raw[start : end+1]
}

func hasDecisionForStage(items []decisionItem, stage string) bool {
	for _, item := range items {
		if item.nextStage == stage {
			return true
		}
	}
	return false
}

func allowedDecisionStages() []string {
	stages := []string{stopDecisionStage, stageTargetReceived}
	for _, module := range availableModules() {
		stages = append(stages, module.startStage)
	}
	sort.Strings(stages)
	return stages
}

func allowedDecisionSet() map[string]struct{} {
	set := map[string]struct{}{}
	for _, stage := range allowedDecisionStages() {
		set[stage] = struct{}{}
	}
	return set
}
