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

	// Insert various vulnerabilities using LogVulnerability
	err = LogVulnerability("target1.com", "SQL Injection", "curl -X POST target1.com/login -d 'user=admin&pass=123'")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	err = LogVulnerability("target2.com", "Cross-Site Scripting", "payload: <script>alert(1)</script>")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	// Retrieve vulnerabilities and verify
	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}

	if len(vulns) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Check content of retrieved vulnerabilities
	expectedMap := map[string]struct {
		finding  string
		testCode string
	}{
		"target1.com": {finding: "SQL Injection", testCode: "curl -X POST target1.com/login -d 'user=admin&pass=123'"},
		"target2.com": {finding: "Cross-Site Scripting", testCode: "payload: <script>alert(1)</script>"},
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
	}
}

