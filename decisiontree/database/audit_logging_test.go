// File overview:
// Test coverage for audit logging. These tests exist to ensure auditable stage
// execution events are persisted with deterministic ordering and schema setup.

package decisiontree

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNewSQLiteAuditLogger_CreatesDatabaseAndSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	auditLogger, err := NewSQLiteAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	t.Cleanup(func() {
		_ = auditLogger.Close()
	})

	if err := auditLogger.LogAction(context.Background(), AuditEvent{
		RunID:    "schema-check",
		Sequence: 1,
		Mode:     "resolver",
		Action:   "schema_test",
		Stage:    "target.received",
		ToolName: "target.received",
		Status:   "succeeded",
		Details:  map[string]any{"ok": true},
	}); err != nil {
		t.Fatalf("log schema check event: %v", err)
	}

	events, err := auditLogger.LookupAuditEvents(context.Background(), "schema-check")
	if err != nil {
		t.Fatalf("lookup schema check events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestSQLiteAuditLogger_LogActionValidation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	auditLogger, err := NewSQLiteAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	t.Cleanup(func() {
		_ = auditLogger.Close()
	})

	if err := auditLogger.LogAction(context.Background(), AuditEvent{}); err == nil {
		t.Fatalf("expected validation error for empty event")
	}
}

func TestRun_LogsAuditEventsWithResolverFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	auditLogger, err := NewSQLiteAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	t.Cleanup(func() {
		_ = auditLogger.Close()
	})

	tree, err := NewTreeWithAuditLogger(newTestLogger(), []ToolDefinition{
		{
			Name: "tool.first",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.first"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.first", Output: map[string]any{"next": "tool.second"}}, nil
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
				return ToolResult{ToolName: "tool.second", Output: map[string]any{"done": true}}, nil
			},
		},
	}, auditLogger)
	if err != nil {
		t.Fatalf("create tree: %v", err)
	}

	if err := tree.Run(context.Background(), ThirdPartyInput{Stage: "tool.first", Payload: map[string]any{"target": "demo"}}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		_ = ctx
		switch result.ToolName {
		case "tool.first":
			return ThirdPartyInput{Stage: "tool.second", Payload: map[string]any{"from": "first"}}, true, nil
		case "tool.second":
			return ThirdPartyInput{Stage: "finished", Payload: map[string]any{"done": true}}, false, nil
		default:
			return ThirdPartyInput{}, false, nil
		}
	}); err != nil {
		t.Fatalf("run resolver flow: %v", err)
	}

	runIDs, err := auditLogger.ListRunIDs(context.Background())
	if err != nil {
		t.Fatalf("list run ids: %v", err)
	}
	if len(runIDs) == 0 {
		t.Fatalf("expected at least one run id")
	}

	events, err := auditLogger.LookupAuditEvents(context.Background(), runIDs[0])
	if err != nil {
		t.Fatalf("lookup audit events: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("expected 6 resolver events, got %d", len(events))
	}
	if events[0].Action != "tool_selection" || events[0].Status != "succeeded" || events[0].Stage != "tool.first" {
		t.Fatalf("unexpected first event: %#v", events[0])
	}
	if events[5].Action != "resolve_next_input" || events[5].Status != "succeeded" {
		t.Fatalf("unexpected final event: %#v", events[5])
	}
}

func TestRunWithPlanner_LogsAuditEventsWithPlannerFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	auditLogger, err := NewSQLiteAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	t.Cleanup(func() {
		_ = auditLogger.Close()
	})

	planner := &scriptedPlanner{
		decisions: []NextToolDecision{
			{Continue: true, NextTool: "tool.second", NextPayload: map[string]any{"from": "planner"}},
			{Continue: false},
		},
	}

	tree, err := NewTreeWithAuditLogger(newTestLogger(), []ToolDefinition{
		{
			Name:        "tool.first",
			Description: "Initial stage",
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
			Description: "Follow-up stage",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "tool.second"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				_ = ctx
				_ = input
				return ToolResult{ToolName: "tool.second", Output: map[string]any{"done": true}}, nil
			},
		},
	}, auditLogger)
	if err != nil {
		t.Fatalf("create tree: %v", err)
	}

	if err := tree.RunWithPlanner(context.Background(), ThirdPartyInput{Stage: "tool.first", Payload: map[string]any{"target": "demo"}}, planner, nil); err != nil {
		t.Fatalf("run planner flow: %v", err)
	}

	runIDs, err := auditLogger.ListRunIDs(context.Background())
	if err != nil {
		t.Fatalf("list run ids: %v", err)
	}
	if len(runIDs) == 0 {
		t.Fatalf("expected at least one run id")
	}

	events, err := auditLogger.LookupAuditEvents(context.Background(), runIDs[0])
	if err != nil {
		t.Fatalf("lookup audit events: %v", err)
	}
	if len(events) != 7 {
		t.Fatalf("expected 7 planner events, got %d", len(events))
	}
	if events[2].Action != "planner_decision" || events[2].Status != "succeeded" {
		t.Fatalf("unexpected first planner decision event: %#v", events[2])
	}
	if events[6].Action != "planner_decision" || events[6].Status != "succeeded" {
		t.Fatalf("unexpected final planner decision event: %#v", events[6])
	}
}
