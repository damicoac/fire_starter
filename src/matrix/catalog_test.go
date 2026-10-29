package matrix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	modules "fire_starter/src/modules/core"
)

// TestCatalog_DecisionsMatchModules asserts every decision in decisions.json
// has a registered module and vice versa, a valid phase, and a unique
// non-empty per-tool description containing the technique name.
func TestCatalog_DecisionsMatchModules(t *testing.T) {
	decisions, err := LoadDecisions()
	if err != nil {
		t.Fatalf("LoadDecisions failed: %v", err)
	}
	if len(decisions) == 0 {
		t.Fatal("no decisions loaded")
	}

	executor, err := NewRealExecutor(decisions)
	if err != nil {
		t.Fatalf("NewRealExecutor failed: %v", err)
	}
	declared := executor.RegisteredTechniques()

	registered := make(map[string]bool)
	for _, m := range modules.RegisteredModuleTechniques() {
		registered[m] = true
	}

	identifiers := make(map[string]bool, len(decisions))
	descriptions := make(map[string]bool, len(decisions))
	for _, d := range decisions {
		technique := strings.ToLower(strings.TrimSpace(d.Technique))

		if _, ok := registered[technique]; !ok {
			t.Errorf("decision %s (%s): no registered module for technique %q", d.Identifier, d.Name(), d.Technique)
		}
		if !declared[technique] {
			t.Errorf("decision %s (%s): technique %q missing from executor registry", d.Identifier, d.Name(), d.Technique)
		}

		if identifiers[d.Identifier] {
			t.Errorf("duplicate decision identifier %q", d.Identifier)
		}
		identifiers[d.Identifier] = true

		if descriptions[d.Description()] {
			t.Errorf("decision %s (%s): duplicate description", d.Identifier, d.Name())
		}
		descriptions[d.Description()] = true

		if !validPhase(d.Phase) {
			t.Errorf("decision %s (%s): invalid phase %q", d.Identifier, d.Name(), d.Phase)
		}

		desc := strings.ToLower(d.Description())
		if strings.TrimSpace(desc) == "" {
			t.Errorf("decision %s (%s): empty description", d.Identifier, d.Name())
		}
		if !strings.Contains(desc, strings.ToLower(d.Technique)) {
			t.Errorf("decision %s (%s): description does not contain the technique name", d.Identifier, d.Name())
		}
	}

	for m := range registered {
		if !declared[m] {
			t.Errorf("registered module %q has no matching decision entry", m)
		}
	}
	for m := range declared {
		if !registered[m] {
			t.Errorf("decision technique %q has no registered module", m)
		}
	}
}

func validPhase(phase string) bool {
	switch Phase(phase) {
	case PhasePreEngagement, PhaseReconnaissance, PhaseScanning, PhaseVulnerabilityAnalysis,
		PhaseExploitation, PhasePostExploitation, PhaseReporting:
		return true
	default:
		return false
	}
}

// TestReadDecisionsFile_OverridesEmbeddedCopy verifies the on-disk file wins
// over the embedded copy, and that the embedded copy is the fallback when the
// file is missing.
func TestReadDecisionsFile_OverridesEmbeddedCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.json")

	if _, err := os.Stat(path); err == nil {
		t.Fatal("expected decisions.json to be absent from temp dir")
	}

	embedded, err := ReadDecisionsFile(path)
	if err != nil {
		t.Fatalf("ReadDecisionsFile fallback failed: %v", err)
	}
	if len(embedded) == 0 {
		t.Fatal("expected embedded decisions fallback")
	}

	content := []byte(`{"decisions":[{"identifier":"t","technique":"t","phase":"reconnaissance"}]}`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	got, err := ReadDecisionsFile(path)
	if err != nil {
		t.Fatalf("ReadDecisionsFile failed: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("expected on-disk file to win, got %q", got)
	}
}
