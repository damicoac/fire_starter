package matrix

import (
	"path/filepath"
	"testing"
)

func TestDatabaseOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fire_starter.db")

	// Initialize database
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// Insert various reports using LogFinalReport
	err = LogFinalReport("target1.com", "Target 1 Report Content", "target")
	if err != nil {
		t.Fatalf("LogFinalReport failed for target: %v", err)
	}

	err = LogFinalReport("target1.com", `{"nodes": []}`, "knowledge graph")
	if err != nil {
		t.Fatalf("LogFinalReport failed for knowledge graph: %v", err)
	}

	err = LogFinalReport("target2.com", "Target 2 Report Content", "target")
	if err != nil {
		t.Fatalf("LogFinalReport failed for target: %v", err)
	}

	err = LogFinalReport("global", "Final Report Content", "final")
	if err != nil {
		t.Fatalf("LogFinalReport failed for final: %v", err)
	}

	// Retrieve target reports and verify
	reports, err := GetTargetReports()
	if err != nil {
		t.Fatalf("GetTargetReports failed: %v", err)
	}

	if len(reports) != 2 {
		t.Errorf("Expected 2 target reports, got %d", len(reports))
	}

	// Check content of retrieved reports
	expectedMap := map[string]string{
		"target1.com": "Target 1 Report Content",
		"target2.com": "Target 2 Report Content",
	}

	for _, rep := range reports {
		expectedContent, ok := expectedMap[rep.TargetDomain]
		if !ok {
			t.Errorf("Unexpected target domain in reports: %s", rep.TargetDomain)
			continue
		}
		if rep.ReportContent != expectedContent {
			t.Errorf("Expected report content %q for target %s, got %q", expectedContent, rep.TargetDomain, rep.ReportContent)
		}
	}
}
