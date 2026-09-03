package core

import (
	"context"
	"testing"
)

func TestSSHPivot_Execute(t *testing.T) {
	// Missing credentials
	testerNoCreds := NewSSHPivot("127.0.0.1", "", "")
	resNoCreds, err := testerNoCreds.Execute(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resNoCreds) == 0 || resNoCreds[0].Status != "error" {
		t.Errorf("expected error status for missing credentials, got %+v", resNoCreds)
	}

	// With credentials
	tester := NewSSHPivot("127.0.0.1", "admin", "secret")
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
}

func TestSSHPivot_Registry(t *testing.T) {
	factory, ok := GetModuleFactory("ssh_pivot")
	if !ok {
		t.Fatal("expected ssh_pivot to be registered")
	}

	mod, err := factory(map[string]any{
		"ip":       "10.0.0.1",
		"username": "root",
		"password": "password123",
	}, func(string) {})
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}

	res, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	results, ok := res.([]SSHPivotResult)
	if !ok {
		t.Fatalf("expected []SSHPivotResult, got %T", res)
	}
	if len(results) == 0 || results[0].Status != "not_implemented" {
		t.Errorf("unexpected results: %+v", results)
	}
}
