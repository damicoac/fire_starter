// File overview:
// Async command wiring between UI and decision-tree execution. It isolates side-effecting work behind Tea commands to keep the update loop responsive and predictable.

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"blackwater/decisiontree"

	tea "github.com/charmbracelet/bubbletea"
)

type stageObserverFunc func(ctx context.Context, input decisiontree.ThirdPartyInput, result *decisiontree.ToolResult) error

func (f stageObserverFunc) OnStageCompleted(ctx context.Context, input decisiontree.ThirdPartyInput, result *decisiontree.ToolResult) error {
	return f(ctx, input, result)
}

func runStageCmd(tree *decisiontree.Tree, input decisiontree.ThirdPartyInput) tea.Cmd {
	return func() tea.Msg {
		if tree == nil {
			return stageExecutedMsg{errorMessage: "decision tree is nil"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		var capturedResult decisiontree.ToolResult
		capturedInput := input
		nextInput := decisiontree.ThirdPartyInput{}
		continueFlow := false
		observer := stageObserverFunc(func(ctx context.Context, current decisiontree.ThirdPartyInput, result *decisiontree.ToolResult) error {
			_ = ctx
			capturedInput = current
			if result != nil {
				capturedResult = *result
			}
			return nil
		})
		if err := tree.RunWithObserver(ctx, input, func(ctx context.Context, result decisiontree.ToolResult) (decisiontree.ThirdPartyInput, bool, error) {
			next, shouldContinue, err := decisiontree.DefaultNextInputResolver(ctx, result)
			if err != nil {
				return decisiontree.ThirdPartyInput{}, false, err
			}
			nextInput = next
			continueFlow = shouldContinue
			return next, false, nil
		}, observer); err != nil {
			return stageExecutedMsg{errorMessage: err.Error()}
		}

		return stageExecutedMsg{
			toolName:      capturedResult.ToolName,
			result:        capturedResult,
			nextInput:     nextInput,
			continueFlow:  continueFlow,
			currentInput:  capturedInput,
			finishedStage: capturedInput.Stage,
		}
	}
}

func buildDecisionsCmd(generator decisiontree.StageGuidanceGenerator, learner decisiontree.ReinforcementLearner, input decisiontree.ThirdPartyInput, result decisiontree.ToolResult, next decisiontree.ThirdPartyInput, continueFlow bool) tea.Cmd {
	return func() tea.Msg {
		items := fallbackDecisions(input, next, continueFlow)
		items = rankDecisionsByReinforcement(learner, input.Stage, items)
		if generator == nil {
			return decisionsReadyMsg{items: items}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		allowedStages := allowedDecisionStages()
		allowedJSON, _ := json.Marshal(allowedStages)
		contextObj := map[string]any{
			"stage":         input.Stage,
			"payload":       input.Payload,
			"tool_name":     result.ToolName,
			"tool_calls":    result.Calls,
			"tool_output":   result.Output,
			"resolver_next": next.Stage,
			"continue_flow": continueFlow,
		}
		contextJSON, _ := json.Marshal(contextObj)

		instructions := "You produce workflow decisions for a defensive security testing app. Return only valid JSON."
		userPrompt := strings.Join([]string{
			"Return exactly 3 decisions in a JSON array.",
			"Each decision object must have keys: title, reason, next_stage.",
			"next_stage must be one of: " + string(allowedJSON),
			"Prioritize practical next actions based on the stage result.",
			"Context:",
			string(contextJSON),
		}, "\n")
		resp, err := generator.GenerateStageGuidance(ctx, instructions, userPrompt)
		if err != nil {
			return decisionsReadyMsg{items: items, err: err}
		}
		parsed := parseLLMDecisions(resp)
		if len(parsed) == 0 {
			return decisionsReadyMsg{items: items}
		}
		merged := mergeWithFallback(parsed, items)
		merged = rankDecisionsByReinforcement(learner, input.Stage, merged)
		return decisionsReadyMsg{items: merged}
	}
}

func rankDecisionsByReinforcement(learner decisiontree.ReinforcementLearner, previousStage string, items []decisionItem) []decisionItem {
	if learner == nil || len(items) == 0 {
		return items
	}

	candidateStages := make([]string, 0, len(items))
	for _, item := range items {
		if item.nextStage == stopDecisionStage {
			continue
		}
		candidateStages = append(candidateStages, item.nextStage)
	}
	if len(candidateStages) == 0 {
		return items
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rankedStages, err := learner.RankNextStages(ctx, previousStage, candidateStages)
	if err != nil {
		return items
	}

	ordered := make([]decisionItem, 0, len(items))
	used := map[int]struct{}{}
	for _, stage := range rankedStages {
		for i, item := range items {
			if item.nextStage != stage {
				continue
			}
			if _, ok := used[i]; ok {
				continue
			}
			ordered = append(ordered, item)
			used[i] = struct{}{}
			break
		}
	}
	for i, item := range items {
		if _, ok := used[i]; ok {
			continue
		}
		ordered = append(ordered, item)
	}
	if len(ordered) > 3 {
		return ordered[:3]
	}
	return ordered
}
