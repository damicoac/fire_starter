package tui

import (
	"strings"
	"testing"
)

func TestFilterLogsByCategory(t *testing.T) {
	entries := []LogEntry{
		{Category: LogCategoryGeneral, Text: "general"},
		{Category: LogCategoryTools, Text: "tool"},
		{Category: LogCategoryChat, Text: "chat"},
		{Category: LogCategoryErrors, Text: "error"},
	}

	got := filterLogs(entries, LogCategoryTools, false)
	if len(got) != 1 || got[0] != "tool" {
		t.Fatalf("filterLogs tools = %v, want [tool]", got)
	}

	got = filterLogs(entries, LogCategoryGeneral, false)
	if len(got) != 4 {
		t.Fatalf("filterLogs all length = %d, want 4", len(got))
	}
}

func TestFilterLogsCollapsesToolSummaries(t *testing.T) {
	entries := []LogEntry{{
		Category: LogCategoryTools,
		Text:     "12:00:00 TOOL_EXECUTION_SUMMARY\nbody line",
	}}

	got := filterLogs(entries, LogCategoryTools, true)
	if len(got) != 1 {
		t.Fatalf("filterLogs collapsed length = %d, want 1", len(got))
	}
	if strings.Contains(got[0], "body line") {
		t.Fatalf("expected collapsed summary to hide body, got %q", got[0])
	}
}

func TestParseKGIncludesVulnerabilityStatuses(t *testing.T) {
	data := []byte(`{
		"targets": {
			"app.example.com": {
				"value": "app.example.com",
				"type": "url",
				"score": 3,
				"current_phase": "vulnerability-analysis",
				"vulnerabilities": ["Candidate fallback"]
			}
		},
		"vulnerability_records": [
			{"TargetDomain": "app.example.com", "Finding": "Confirmed SQL injection", "Status": "confirmed", "Severity": "high"},
			{"TargetDomain": "app.example.com", "Finding": "Server header", "Status": "informational", "Severity": "informational"}
		]
	}`)

	targets := parseKG(data, nil)
	if len(targets) != 1 {
		t.Fatalf("expected one target, got %#v", targets)
	}
	if len(targets[0].VulnerabilityDetails) != 2 {
		t.Fatalf("expected vulnerability details with statuses, got %#v", targets[0].VulnerabilityDetails)
	}
	if targets[0].VulnerabilityDetails[0].Status != "confirmed" || targets[0].VulnerabilityDetails[0].Severity != "high" || targets[0].VulnerabilityDetails[0].Finding != "Confirmed SQL injection" {
		t.Fatalf("unexpected first vulnerability detail: %#v", targets[0].VulnerabilityDetails[0])
	}
}

func TestStatusBarShowsCurrentMode(t *testing.T) {
	m := InitialModel()
	m.width = 80
	m.activePane = 1
	m.activeLogFilter = LogCategoryErrors
	m.inspectorMode = true
	m.kgTargets = []KGTarget{{Value: "example.com"}}

	view := m.statusBarView()
	for _, expected := range []string{"Pane: Knowledge Graph", "Mode: Inspector", "Filter: Errors", "Targets: 1"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("statusBarView missing %q in %q", expected, view)
		}
	}
}
