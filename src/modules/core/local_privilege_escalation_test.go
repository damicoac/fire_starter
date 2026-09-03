package core

import (
	"context"
	"testing"
)

func TestLocalPrivilegeEscalation_Execute(t *testing.T) {
	tester := NewLocalPrivilegeEscalation("127.0.0.1")
	results, err := tester.Execute(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Status != "not_implemented" {
		t.Errorf("expected status 'not_implemented', got %s", results[0].Status)
	}

	if results[0].Target != "127.0.0.1" {
		t.Errorf("expected target '127.0.0.1', got %s", results[0].Target)
	}
}

func TestLocalPrivilegeEscalation_Registry(t *testing.T) {
	factory, ok := GetModuleFactory("local_privilege_escalation")
	if !ok {
		t.Fatal("expected local_privilege_escalation to be registered")
	}

	mod, err := factory(map[string]any{"ip": "10.0.0.1"}, func(string) {})
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}

	res, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	results, ok := res.([]LocalPrivilegeEscalationResult)
	if !ok {
		t.Fatalf("expected []LocalPrivilegeEscalationResult, got %T", res)
	}
	if len(results) == 0 || results[0].Status != "not_implemented" {
		t.Errorf("unexpected results: %+v", results)
	}
}
