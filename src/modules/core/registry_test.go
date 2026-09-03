package core

import (
	"context"
	"testing"
)

func TestModuleRegistry(t *testing.T) {
	testModuleName := "custom_test_module"
	called := false

	RegisterModule(testModuleName, func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		called = true
		return ModuleWrapper{
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return "ok", nil
			},
		}, nil
	})

	factory, ok := GetModuleFactory(testModuleName)
	if !ok {
		t.Fatalf("expected factory to be registered for %s", testModuleName)
	}

	mod, err := factory(nil, func(string) {})
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}
	if !called {
		t.Error("expected factory to have been invoked")
	}

	res, err := mod.Execute(context.Background())
	if err != nil || res != "ok" {
		t.Errorf("expected 'ok', got %v, err: %v", res, err)
	}
}

func TestPayloadHelpers(t *testing.T) {
	payload := map[string]any{
		"str_val":   "hello",
		"int_val":   42,
		"float_val": 3.14,
		"bool_val":  true,
	}

	if val := PayloadString(payload, "str_val", "default"); val != "hello" {
		t.Errorf("expected 'hello', got %s", val)
	}
	if val := PayloadString(payload, "missing", "default"); val != "default" {
		t.Errorf("expected 'default', got %s", val)
	}

	if val := PayloadInt(payload, "int_val", 0); val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
	if val := PayloadInt(payload, "float_val", 0); val != 3 {
		t.Errorf("expected 3, got %d", val)
	}
	if val := PayloadInt(payload, "missing", 10); val != 10 {
		t.Errorf("expected 10, got %d", val)
	}

	if val := PayloadBool(payload, "bool_val", false); !val {
		t.Errorf("expected true, got %v", val)
	}
	if val := PayloadBool(payload, "missing", true); !val {
		t.Errorf("expected true, got %v", val)
	}
}
