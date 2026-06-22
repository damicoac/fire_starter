package matrix

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestDatabaseOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fire_starter.db")

	// Reset singleton for isolated test DB
	dbInstance = nil
	dbOnce = sync.Once{}

	// Initialize database
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// Insert vulnerabilities using LogVulnerability
	err = LogVulnerability("vid-1", "target1.com", "SQL Injection", "poc-1", "no", "no")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	err = LogVulnerability("vid-2", "target2.com", "Cross-Site Scripting", "poc-2", "yes", "yes")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	// Upsert existing vulnerability
	err = LogVulnerability("vid-1", "target1.com", "SQL Injection", "poc-1-updated", "yes", "yes")
	if err != nil {
		t.Fatalf("LogVulnerability upsert failed: %v", err)
	}

	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}

	if len(vulns) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(vulns))
	}

	expectedMap := map[string]struct {
		finding      string
		testCode     string
		exploitable  string
		processed    string
	}{
		"target1.com": {finding: "SQL Injection", testCode: "poc-1-updated", exploitable: "yes", processed: "yes"},
		"target2.com": {finding: "Cross-Site Scripting", testCode: "poc-2", exploitable: "yes", processed: "yes"},
	}

	for _, v := range vulns {
		expected, ok := expectedMap[v.TargetDomain]
		if !ok {
			t.Errorf("Unexpected target domain in vulnerabilities: %s", v.TargetDomain)
			continue
		}
		if v.Finding != expected.finding {
			t.Errorf("Expected finding %q for target %s, got %q", expected.finding, v.TargetDomain, v.Finding)
		}
		if v.TestCode != expected.testCode {
			t.Errorf("Expected test code %q for target %s, got %q", expected.testCode, v.TargetDomain, v.TestCode)
		}
		if v.Exploitable != expected.exploitable {
			t.Errorf("Expected exploitable %q for target %s, got %q", expected.exploitable, v.TargetDomain, v.Exploitable)
		}
		if v.Processed != expected.processed {
			t.Errorf("Expected processed %q for target %s, got %q", expected.processed, v.TargetDomain, v.Processed)
		}
	}
}
