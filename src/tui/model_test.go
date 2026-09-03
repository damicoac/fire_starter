package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
	m.kgTargets = []KGTarget{{Value: "example.com"}}

	view := m.statusBarView()
	for _, expected := range []string{"View: 1 Execution Logs", "Focus: Right Pane", "Filter: Errors", "Targets: 1"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("statusBarView missing %q in %q", expected, view)
		}
	}
}

func TestTabTogglesFocus(t *testing.T) {
	m := InitialModel()
	if m.activePane != 0 || m.activeTab != 0 {
		t.Fatalf("initial state: activePane=%d, activeTab=%d, expected 0, 0", m.activePane, m.activeTab)
	}

	// Press Tab -> activePane=1 (Right Pane), activeTab stays 0
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	if m.activePane != 1 || m.activeTab != 0 {
		t.Fatalf("after 1st tab: activePane=%d, activeTab=%d, expected 1, 0", m.activePane, m.activeTab)
	}

	// Press Tab again -> activePane=0 (Left Pane), activeTab stays 0
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	if m.activePane != 0 || m.activeTab != 0 {
		t.Fatalf("after 2nd tab: activePane=%d, activeTab=%d, expected 0, 0", m.activePane, m.activeTab)
	}
}

func TestNumberKeysSwitchViews(t *testing.T) {
	m := InitialModel()

	// Press '2' -> View 2 (Site Map)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = updated.(Model)
	if m.activeTab != 1 {
		t.Fatalf("press '2': activeTab=%d, expected 1", m.activeTab)
	}

	// Press '3' -> View 3 (Knowledge Base & Findings)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = updated.(Model)
	if m.activeTab != 2 {
		t.Fatalf("press '3': activeTab=%d, expected 2", m.activeTab)
	}

	// Press '1' -> View 1 (Execution Logs)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m = updated.(Model)
	if m.activeTab != 0 {
		t.Fatalf("press '1': activeTab=%d, expected 0", m.activeTab)
	}
}

func TestBuildSiteMapView_HierarchicalTree(t *testing.T) {
	targets := []KGTarget{
		{
			Value: "example.com",
			Score: 10,
			CurrentPhase: "reconnaissance",
			DiscoveredURLs: []string{
				"http://example.com/api/v1/users",
				"http://example.com/api/v1/posts",
				"http://example.com/auth/login?redirect=dash",
			},
		},
	}

	view := buildSiteMapView(targets, 80)

	expectedSubstrings := []string{
		"Target Site Map & Topology",
		"▼ 🌐 example.com",
		"📁 / (root surface)",
		"📁 api",
		"📁 v1",
		"📄 users",
		"📄 posts",
		"📁 auth",
		"📄 login",
		"?redirect",
	}

	for _, exp := range expectedSubstrings {
		if !strings.Contains(view, exp) {
			t.Errorf("expected site map view to contain %q, but got:\n%s", exp, view)
		}
	}
}


