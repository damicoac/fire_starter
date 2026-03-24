// File overview:
// Execution loop orchestration for resolver-driven and planner-driven modes. It exists to enforce consistent stage progression, observer hooks, and failure handling across all workflows.

package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// StageObserver is an extension hook invoked after each stage execution.
// It exists so integrations (for example, guidance injectors) can enrich
// outputs without coupling their logic to the core loop implementation.
type StageObserver interface {
	OnStageCompleted(ctx context.Context, input ThirdPartyInput, result *ToolResult) error
}

// LLMToolPlanner decides the next tool from the latest stage result.
// Using an interface keeps planner strategy replaceable (mocked, heuristic, or
// model-backed) while the loop remains unchanged.
type LLMToolPlanner interface {
	DecideNextTool(ctx context.Context, result ToolResult, tools []ToolDescriptor) (NextToolDecision, error)
}

// NextToolDecision is the planner's normalized handoff payload.
// It keeps continuation intent, selected tool, and payload bundled together so
// planner output can be validated and executed atomically.
type NextToolDecision struct {
	NextTool    string
	NextPayload map[string]any
	Continue    bool
}

type runAuditState struct {
	runID    string
	mode     string
	sequence int
}

func newRunAuditState(mode string) runAuditState {
	return runAuditState{
		runID: fmt.Sprintf("%d", time.Now().UTC().UnixNano()),
		mode:  mode,
	}
}

func (s *runAuditState) nextEvent(action string, stage string, toolName string, status string, details map[string]any) AuditEvent {
	s.sequence++
	return AuditEvent{
		RunID:    s.runID,
		Sequence: s.sequence,
		Mode:     s.mode,
		Action:   action,
		Stage:    stage,
		ToolName: toolName,
		Status:   status,
		Details:  details,
	}
}

func (t *Tree) logAuditEvent(ctx context.Context, state *runAuditState, action string, stage string, toolName string, status string, details map[string]any) error {
	if t == nil || t.auditLogger == nil || state == nil {
		return nil
	}
	return t.auditLogger.LogAction(ctx, state.nextEvent(action, stage, toolName, status, details))
}

func (t *Tree) Run(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver) error {
	return t.RunWithObserver(ctx, initial, resolve, nil)
}

func (t *Tree) RunWithObserver(ctx context.Context, initial ThirdPartyInput, resolve NextInputResolver, observer StageObserver) error {
	if resolve == nil {
		return errors.New("next input resolver is required")
	}

	auditState := newRunAuditState("resolver")
	current := initial
	for {
		tool, err := t.SelectTool(current)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "tool_selection", current.Stage, "", "failed", map[string]any{"error": err.Error()})
			t.logger.Error("tool selection failed", "stage", current.Stage, "err", err)
			return err
		}

		if err := t.logAuditEvent(ctx, &auditState, "tool_selection", current.Stage, tool.Name, "succeeded", map[string]any{"payload_keys": len(current.Payload)}); err != nil {
			t.logger.Error("audit logging failed", "action", "tool_selection", "stage", current.Stage, "tool", tool.Name, "err", err)
			return err
		}
		t.logger.Info("tool selected", "tool", tool.Name, "stage", current.Stage)
		result, err := tool.Run(ctx, current)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "tool_execution", current.Stage, tool.Name, "failed", map[string]any{"error": err.Error()})
			t.logger.Error("tool execution failed", "tool", tool.Name, "stage", current.Stage, "err", err)
			return err
		}
		if err := t.logAuditEvent(ctx, &auditState, "tool_execution", current.Stage, result.ToolName, "succeeded", map[string]any{"call_count": len(result.Calls), "execution_count": len(result.Executions)}); err != nil {
			t.logger.Error("audit logging failed", "action", "tool_execution", "stage", current.Stage, "tool", result.ToolName, "err", err)
			return err
		}

		if observer != nil {
			err = observer.OnStageCompleted(ctx, current, &result)
			if err != nil {
				_ = t.logAuditEvent(ctx, &auditState, "observer", current.Stage, result.ToolName, "failed", map[string]any{"error": err.Error()})
				t.logger.Error("stage observer failed", "tool", result.ToolName, "stage", current.Stage, "err", err)
				return err
			}
			if err := t.logAuditEvent(ctx, &auditState, "observer", current.Stage, result.ToolName, "succeeded", map[string]any{}); err != nil {
				t.logger.Error("audit logging failed", "action", "observer", "stage", current.Stage, "tool", result.ToolName, "err", err)
				return err
			}
		}

		t.logger.Info("tool completed", "tool", result.ToolName)
		next, continueFlow, err := resolve(ctx, result)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "resolve_next_input", current.Stage, result.ToolName, "failed", map[string]any{"error": err.Error()})
			t.logger.Error("resolver failed", "tool", result.ToolName, "err", err)
			return err
		}
		if err := t.logAuditEvent(ctx, &auditState, "resolve_next_input", next.Stage, result.ToolName, "succeeded", map[string]any{"continue": continueFlow, "next_payload_keys": len(next.Payload)}); err != nil {
			t.logger.Error("audit logging failed", "action", "resolve_next_input", "stage", next.Stage, "tool", result.ToolName, "err", err)
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

	auditState := newRunAuditState("planner")
	current := initial
	catalog := t.ToolCatalog()
	pendingPrevious := ""
	pendingCurrent := ""

	for {
		tool, err := t.SelectTool(current)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "tool_selection", current.Stage, "", "failed", map[string]any{"error": err.Error()})
			t.logger.Error("tool selection failed", "stage", current.Stage, "err", err)
			if learner != nil && pendingPrevious != "" {
				_ = learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, -1)
			}
			return err
		}

		if err := t.logAuditEvent(ctx, &auditState, "tool_selection", current.Stage, tool.Name, "succeeded", map[string]any{"payload_keys": len(current.Payload)}); err != nil {
			t.logger.Error("audit logging failed", "action", "tool_selection", "stage", current.Stage, "tool", tool.Name, "err", err)
			return err
		}
		t.logger.Info("tool selected", "tool", tool.Name, "stage", current.Stage)
		result, err := tool.Run(ctx, current)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "tool_execution", current.Stage, tool.Name, "failed", map[string]any{"error": err.Error()})
			t.logger.Error("tool execution failed", "tool", tool.Name, "stage", current.Stage, "err", err)
			if learner != nil && pendingPrevious != "" {
				_ = learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, -1)
			}
			return err
		}
		if err := t.logAuditEvent(ctx, &auditState, "tool_execution", current.Stage, result.ToolName, "succeeded", map[string]any{"call_count": len(result.Calls), "execution_count": len(result.Executions)}); err != nil {
			t.logger.Error("audit logging failed", "action", "tool_execution", "stage", current.Stage, "tool", result.ToolName, "err", err)
			return err
		}
		if learner != nil && pendingPrevious != "" {
			if err := learner.RecordTransition(ctx, pendingPrevious, pendingCurrent, 1); err != nil {
				t.logger.Error("reinforcement logging failed", "from", pendingPrevious, "to", pendingCurrent, "err", err)
				return err
			}
			if err := t.logAuditEvent(ctx, &auditState, "reinforcement_transition", pendingPrevious, pendingCurrent, "succeeded", map[string]any{"reward": 1}); err != nil {
				t.logger.Error("audit logging failed", "action", "reinforcement_transition", "stage", pendingPrevious, "tool", pendingCurrent, "err", err)
				return err
			}
			pendingPrevious = ""
			pendingCurrent = ""
		}

		if observer != nil {
			err = observer.OnStageCompleted(ctx, current, &result)
			if err != nil {
				_ = t.logAuditEvent(ctx, &auditState, "observer", current.Stage, result.ToolName, "failed", map[string]any{"error": err.Error()})
				t.logger.Error("stage observer failed", "tool", result.ToolName, "stage", current.Stage, "err", err)
				return err
			}
			if err := t.logAuditEvent(ctx, &auditState, "observer", current.Stage, result.ToolName, "succeeded", map[string]any{}); err != nil {
				t.logger.Error("audit logging failed", "action", "observer", "stage", current.Stage, "tool", result.ToolName, "err", err)
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
			if err := t.logAuditEvent(ctx, &auditState, "reinforcement_ranking", current.Stage, "", "succeeded", map[string]any{"candidate_count": len(decisionTools), "ranked_count": len(rankedNames)}); err != nil {
				t.logger.Error("audit logging failed", "action", "reinforcement_ranking", "stage", current.Stage, "err", err)
				return err
			}
			decisionTools = reorderToolCatalogByName(decisionTools, rankedNames)
		}

		decision, err := planner.DecideNextTool(ctx, result, decisionTools)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "planner_decision", current.Stage, result.ToolName, "failed", map[string]any{"error": err.Error()})
			t.logger.Error("llm planner failed", "tool", result.ToolName, "err", err)
			return err
		}
		if err := t.logAuditEvent(ctx, &auditState, "planner_decision", current.Stage, result.ToolName, "succeeded", map[string]any{"continue": decision.Continue, "next_tool": decision.NextTool, "next_payload_keys": len(decision.NextPayload)}); err != nil {
			t.logger.Error("audit logging failed", "action", "planner_decision", "stage", current.Stage, "tool", result.ToolName, "err", err)
			return err
		}
		if !decision.Continue {
			t.logger.Info("decision flow complete", "last_tool", result.ToolName)
			return nil
		}

		nextTool, err := t.SelectToolByName(decision.NextTool)
		if err != nil {
			_ = t.logAuditEvent(ctx, &auditState, "planner_target_validation", current.Stage, decision.NextTool, "failed", map[string]any{"error": err.Error()})
			t.logger.Error("planner selected unknown tool", "tool", decision.NextTool, "err", err)
			if learner != nil {
				_ = learner.RecordTransition(ctx, current.Stage, decision.NextTool, -1)
			}
			return err
		}
		if err := t.logAuditEvent(ctx, &auditState, "planner_target_validation", current.Stage, nextTool.Name, "succeeded", map[string]any{}); err != nil {
			t.logger.Error("audit logging failed", "action", "planner_target_validation", "stage", current.Stage, "tool", nextTool.Name, "err", err)
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

// toolCatalogNames projects descriptors into stage/tool names for ranking APIs.
// This keeps ranking logic independent of descriptive metadata.
func toolCatalogNames(catalog []ToolDescriptor) []string {
	names := make([]string, len(catalog))
	for i := range catalog {
		names[i] = catalog[i].Name
	}
	return names
}

// reorderToolCatalogByName applies learner-prioritized ordering while preserving
// any uncategorized tools as a stable tail for deterministic fallbacks.
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
