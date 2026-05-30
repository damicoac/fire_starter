package matrix

import "testing"

func TestToolRegistry_SortsAndLooksUpByIdentifier(t *testing.T) {
	decisions := []Decision{
		{Identifier: "002", Technique: "port_scanning", UseCase: "u2", Function: "f2", ProblemTheToolSolves: "p2"},
		{Identifier: "001", Technique: "google_dorking", UseCase: "u1", Function: "f1", ProblemTheToolSolves: "p1"},
	}

	registry := NewToolRegistry(decisions)
	tools := registry.ListTools()

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Identifier != "001" || tools[1].Identifier != "002" {
		t.Fatalf("expected tools sorted by identifier, got %q then %q", tools[0].Identifier, tools[1].Identifier)
	}

	tool, ok := registry.ToolForIdentifier("002")
	if !ok {
		t.Fatal("expected tool lookup by identifier to succeed")
	}
	if tool.Name != "decision_port_scanning" {
		t.Fatalf("expected normalized tool name, got %q", tool.Name)
	}
	if tool.Technique != "port_scanning" {
		t.Fatalf("expected preserved technique, got %q", tool.Technique)
	}
}

func TestToolRegistry_ListToolsReturnsCopy(t *testing.T) {
	registry := NewToolRegistry([]Decision{{Identifier: "001", Technique: "google_dorking", UseCase: "u", Function: "f", ProblemTheToolSolves: "p"}})

	first := registry.ListTools()
	first[0].Name = "tampered"

	second := registry.ListTools()
	if second[0].Name == "tampered" {
		t.Fatal("expected ListTools to return a copy, but mutation leaked")
	}
}

func TestToolNameFromDecision_NormalizationAndFallback(t *testing.T) {
	name := toolNameFromDecision(Decision{Identifier: "123", Technique: "  SQL Injection-Test!  "})
	if name != "decision_sql_injection_test" {
		t.Fatalf("unexpected normalized name %q", name)
	}

	fallback := toolNameFromDecision(Decision{Identifier: "999", Technique: "***"})
	if fallback != "decision_decision_999" {
		t.Fatalf("unexpected fallback name %q", fallback)
	}
}

func TestToolNameFromDecision_TrimsUnderscoresAndSpecialChars(t *testing.T) {
	name := toolNameFromDecision(Decision{Identifier: "777", Technique: "__GraphQL---INTROSPECTION!!__"})
	if name != "decision_graphql___introspection" {
		t.Fatalf("unexpected normalized name %q", name)
	}
}

func TestToolRegistry_InputSchemaAnyOfContract(t *testing.T) {
	registry := NewToolRegistry([]Decision{{Identifier: "001", Technique: "google_dorking", UseCase: "u", Function: "f", ProblemTheToolSolves: "p"}})
	tools := registry.ListTools()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	anyOf, ok := tools[0].InputSchema["anyOf"].([]map[string]any)
	if !ok {
		t.Fatalf("expected anyOf to be []map[string]any, got %T", tools[0].InputSchema["anyOf"])
	}
	if len(anyOf) != 3 {
		t.Fatalf("expected 3 anyOf alternatives, got %d", len(anyOf))
	}
}
