// File overview:
// Test coverage for this module. These tests exist to lock expected behavior and prevent regressions in stage routing, payload handling, and integration boundaries.

package decisiontree

import (
	"context"
	"errors"
	"testing"
)

type scriptedPlanner struct {
	decisions    []NextToolDecision
	err          error
	cursor       int
	seenResults  []ToolResult
	seenCatalogs [][]ToolDescriptor
}

func (p *scriptedPlanner) DecideNextTool(ctx context.Context, result ToolResult, tools []ToolDescriptor) (NextToolDecision, error) {
	_ = ctx
	if p.err != nil {
		return NextToolDecision{}, p.err
	}
	p.seenResults = append(p.seenResults, result)
	p.seenCatalogs = append(p.seenCatalogs, append([]ToolDescriptor(nil), tools...))
	if p.cursor >= len(p.decisions) {
		return NextToolDecision{Continue: false}, nil
	}
	decision := p.decisions[p.cursor]
	p.cursor++
	return decision, nil
}

type reinforcementRecord struct {
	previousStage string
	currentStage  string
	reward        int
}

type reinforcementRankCall struct {
	previousStage string
	candidates    []string
}

type scriptedReinforcementLearner struct {
	rankings  []string
	recordErr error
	rankErr   error
	records   []reinforcementRecord
	rankCalls []reinforcementRankCall
}

func (l *scriptedReinforcementLearner) RecordTransition(ctx context.Context, previousStage string, currentStage string, reward int) error {
	_ = ctx
	l.records = append(l.records, reinforcementRecord{previousStage: previousStage, currentStage: currentStage, reward: reward})
	if l.recordErr != nil {
		return l.recordErr
	}
	return nil
}

func (l *scriptedReinforcementLearner) RankNextStages(ctx context.Context, previousStage string, candidates []string) ([]string, error) {
	_ = ctx
	l.rankCalls = append(l.rankCalls, reinforcementRankCall{previousStage: previousStage, candidates: append([]string(nil), candidates...)})
	if l.rankErr != nil {
		return nil, l.rankErr
	}
	if len(l.rankings) == 0 {
		return append([]string(nil), candidates...), nil
	}
	return append([]string(nil), l.rankings...), nil
}

func (l *scriptedReinforcementLearner) Close() error {
	return nil
}

func TestRunWithPlanner_ExecutesFirstToolThenPlannerSelectedTool(t *testing.T) {
	called := make([]string, 0, 2)
	secondPayload := map[string]any{}
	planner := &scriptedPlanner{
		decisions: []NextToolDecision{
			{Continue: true, NextTool: "tool.second", NextPayload: map[string]any{"from": "planner"}},
			{Continue: false},
		},
	}
	logMockData(t, "run-with-planner scripted decisions", planner.decisions)

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name:        "tool.first",
			Description: "Initial reconnaissance stage",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				called = append(called, "tool.first")
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
		{
			Name:        "tool.second",
			Description: "Follow-up validation stage",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.second"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				called = append(called, "tool.second")
				secondPayload = CopyPayload(input.Payload)
				return ToolResult{ToolName: "tool.second", Output: map[string]any{"done": true}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlanner(context.Background(), ThirdPartyInput{Stage: "tool.first", Payload: map[string]any{"target": "demo"}}, planner, nil)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if len(called) != 2 || called[0] != "tool.first" || called[1] != "tool.second" {
		t.Fatalf("unexpected call order: %v", called)
	}
	if secondPayload["from"] != "planner" {
		t.Fatalf("expected planner payload to be passed to second tool, payload: %#v", secondPayload)
	}
	if len(planner.seenCatalogs) == 0 || len(planner.seenCatalogs[0]) != 2 {
		t.Fatalf("expected full tool catalog in planner call, catalogs: %#v", planner.seenCatalogs)
	}
}

func TestRunWithPlanner_ReturnsErrorForUnknownPlannerTool(t *testing.T) {
	planner := &scriptedPlanner{
		decisions: []NextToolDecision{{Continue: true, NextTool: "tool.missing"}},
	}
	logMockData(t, "unknown-tool scripted decisions", planner.decisions)

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "tool.first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlanner(context.Background(), ThirdPartyInput{Stage: "tool.first"}, planner, nil)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("expected ErrUnknownTool, got %v", err)
	}
}

func TestRunWithPlanner_ReturnsErrorForNilPlanner(t *testing.T) {
	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "tool.first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlanner(context.Background(), ThirdPartyInput{Stage: "tool.first"}, nil, nil)
	if err == nil {
		t.Fatalf("expected nil planner error")
	}
}

func TestRunWithPlannerAndReinforcement_UsesRankingAndLogsSuccess(t *testing.T) {
	planner := &scriptedPlanner{
		decisions: []NextToolDecision{
			{Continue: true, NextTool: "tool.second"},
			{Continue: false},
		},
	}
	learner := &scriptedReinforcementLearner{rankings: []string{"tool.second", "tool.third", "tool.first"}}
	logMockData(t, "reinforcement-success scripted decisions", planner.decisions)
	logMockData(t, "reinforcement-success scripted rankings", learner.rankings)

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name:        "tool.first",
			Description: "first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
		{
			Name:        "tool.second",
			Description: "second",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.second"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.second", Output: map[string]any{"status": "ok"}}, nil
			},
		},
		{
			Name:        "tool.third",
			Description: "third",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.third"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.third", Output: map[string]any{"status": "ok"}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlannerAndReinforcement(context.Background(), ThirdPartyInput{Stage: "tool.first"}, planner, nil, learner)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if len(planner.seenCatalogs) < 1 || len(planner.seenCatalogs[0]) < 2 {
		t.Fatalf("expected planner catalog entries, got %#v", planner.seenCatalogs)
	}
	if planner.seenCatalogs[0][0].Name != "tool.second" {
		t.Fatalf("expected ranked tool.second first, got %#v", planner.seenCatalogs[0])
	}
	if len(learner.rankCalls) == 0 || learner.rankCalls[0].previousStage != "tool.first" {
		t.Fatalf("expected rank call for tool.first, calls: %#v", learner.rankCalls)
	}
	if len(learner.records) != 1 {
		t.Fatalf("expected one reinforcement record, got %#v", learner.records)
	}
	if learner.records[0].previousStage != "tool.first" || learner.records[0].currentStage != "tool.second" || learner.records[0].reward != 1 {
		t.Fatalf("unexpected reinforcement success record: %#v", learner.records[0])
	}
}

func TestRunWithPlannerAndReinforcement_LogsFailureWhenNextStageFails(t *testing.T) {
	expectedErr := errors.New("tool.second failed")
	planner := &scriptedPlanner{
		decisions: []NextToolDecision{{Continue: true, NextTool: "tool.second"}},
	}
	learner := &scriptedReinforcementLearner{}
	logMockData(t, "reinforcement-failure scripted decisions", planner.decisions)

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "tool.first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
		{
			Name: "tool.second",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.second"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{}, expectedErr
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlannerAndReinforcement(context.Background(), ThirdPartyInput{Stage: "tool.first"}, planner, nil, learner)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected tool.second error, got %v", err)
	}
	if len(learner.records) != 1 {
		t.Fatalf("expected one reinforcement record, got %#v", learner.records)
	}
	if learner.records[0].previousStage != "tool.first" || learner.records[0].currentStage != "tool.second" || learner.records[0].reward != -1 {
		t.Fatalf("unexpected reinforcement failure record: %#v", learner.records[0])
	}
}

func TestRunWithPlannerAndReinforcement_RequiresLearner(t *testing.T) {
	planner := &scriptedPlanner{}
	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "tool.first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"status": "ok"}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithPlannerAndReinforcement(context.Background(), ThirdPartyInput{Stage: "tool.first"}, planner, nil, nil)
	if err == nil {
		t.Fatalf("expected nil learner error")
	}
}
