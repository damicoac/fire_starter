package core

import (
	"context"
	"errors"
)

type StageObserver interface {
	OnStageCompleted(ctx context.Context, input ThirdPartyInput, result *ToolResult) error
}

type LLMToolPlanner interface {
	DecideNextTool(ctx context.Context, result ToolResult, tools []ToolDescriptor) (NextToolDecision, error)
}

type NextToolDecision struct {
	NextTool    string
	NextPayload map[string]any
	Continue    bool
}

func (t *Tree) Run(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver) error {
	return t.RunWithObserver(ctx, initial, resolve, nil)
}

func (t *Tree) RunWithObserver(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver, observer StageObserver) error {
	if resolve == nil {
		return errors.New("next input resolver is required")
	}

	current := initial
	for {
		tool, err := t.SelectTool(current)
		if err != nil {
			t.logger.Error("tool selection failed", "stage", current.Stage, "err", err)
			return err
		}

		t.logger.Info("tool selected", "tool", tool.Name, "stage", current.Stage)
		result, err := tool.Run(ctx, current)
		if err != nil {
			t.logger.Error("tool execution failed", "tool", tool.Name, "stage", current.Stage, "err", err)
			return err
		}

		if observer != nil {
			err = observer.OnStageCompleted(ctx, current, &result)
			if err != nil {
				t.logger.Error("stage observer failed", "tool", result.ToolName, "stage", current.Stage, "err", err)
				return err
			}
		}

		t.logger.Info("tool completed", "tool", result.ToolName)
		next, continueFlow, err := resolve(ctx, result)
		if err != nil {
			t.logger.Error("resolver failed", "tool", result.ToolName, "err", err)
			return err
		}
		if !continueFlow {
			t.logger.Info("decision flow complete", "last_tool", result.ToolName)
			return nil
		}

		current = next
	}
}

func (t *Tree) RunWithPlanner(ctx context.Context, initial ThirdPartyInput, planner LLMToolPlanner, observer StageObserver) error {
	return t.runWithPlanner(ctx, initial, planner, observer, nil)
}

func (t *Tree) RunWithPlannerAndReinforcement(ctx context.Context, initial ThirdPartyInput, planner LLMToolPlanner, observer StageObserver, learner ReinforcementLearner) error {
	if learner == nil {
		return errors.New("reinforcement learner is required")
	}
	return t.runWithPlanner(ctx, initial, planner, observer, learner)
}

func (t *Tree) runWithPlanner(ctx context.Context, initial ThirdPartyInput, planner LLMToolPlanner, observer StageObserver, learner ReinforcementLearner) error {
	if planner == nil {
		return errors.New("llm tool planner is required")
	}

	current := initial
	catalog := t.ToolCatalog()
	pendingPrevious := ""
	pendingCurrent := ""

	for {
		tool, err := t.SelectTool(current)
		if err != nil {
			t.logger.Error("tool selection failed", "stage", current.Stage, "err", err)
			if learner != nil && pendingPrevious != "" {
				_ = learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, -1)
			}
			return err
		}

		t.logger.Info("tool selected", "tool", tool.Name, "stage", current.Stage)
		result, err := tool.Run(ctx, current)
		if err != nil {
			t.logger.Error("tool execution failed", "tool", tool.Name, "stage", current.Stage, "err", err)
			if learner != nil && pendingPrevious != "" {
				_ = learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, -1)
			}
			return err
		}
		if learner != nil && pendingPrevious != "" {
			if err := learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, 1); err != nil {
				t.logger.Error("reinforcement logging failed", "from", pendingPrevious, "to", pendingCurrent, "err", err)
				return err
			}
			pendingPrevious = ""
			pendingCurrent = ""
		}

		if observer != nil {
			err = observer.OnStageCompleted(ctx, current, &result)
			if err != nil {
				t.logger.Error("stage observer failed", "tool", result.ToolName, "stage", current.Stage, "err", err)
				return err
			}
		}

		t.logger.Info("tool completed", "tool", result.ToolName)
		decisionTools := append([]ToolDescriptor(nil), catalog...)
		if learner != nil {
			rankedNames, err := learner.RankNextStages(ctx, current.Stage, toolCatalogNames(decisionTools))
			if err != nil {
				t.logger.Error("reinforcement ranking failed", "stage", current.Stage, "err", err)
				return err
			}
			decisionTools = reorderToolCatalogByName(decisionTools, rankedNames)
		}

		decision, err := planner.DecideNextTool(ctx, result, decisionTools)
		if err != nil {
			t.logger.Error("llm planner failed", "tool", result.ToolName, "err", err)
			return err
		}
		if !decision.Continue {
			t.logger.Info("decision flow complete", "last_tool", result.ToolName)
			return nil
		}

		nextTool, err := t.SelectToolByName(decision.NextTool)
		if err != nil {
			t.logger.Error("planner selected unknown tool", "tool", decision.NextTool, "err", err)
			if learner != nil {
				_ = learner.RecordTransition(ctx, current.Stage, decision.NextTool, -1)
			}
			return err
		}

		nextPayload := map[string]any{}
		if decision.NextPayload != nil {
			nextPayload = copyPayload(decision.NextPayload)
		}
		if learner != nil {
			pendingPrevious = current.Stage
			pendingCurrent = nextTool.Name
		}
		current = ThirdPartyInput{Stage: nextTool.Name, Payload: nextPayload}
	}
}

func toolCatalogNames(catalog []ToolDescriptor) []string {
	names := make([]string, len(catalog))
	for i := range catalog {
		names[i] = catalog[i].Name
	}
	return names
}

func reorderToolCatalogByName(catalog []ToolDescriptor, orderedNames []string) []ToolDescriptor {
	position := map[string]int{}
	for i, name := range orderedNames {
		position[name] = i
	}
	ordered := make([]ToolDescriptor, 0, len(catalog))
	seen := map[string]struct{}{}
	for _, name := range orderedNames {
		for _, tool := range catalog {
			if tool.Name == name {
				ordered = append(ordered, tool)
				seen[tool.Name] = struct{}{}
				break
			}
		}
	}
	for _, tool := range catalog {
		if _, ok := seen[tool.Name]; ok {
			continue
		}
		if _, ok := position[tool.Name]; !ok {
			ordered = append(ordered, tool)
		}
	}
	return ordered
}
