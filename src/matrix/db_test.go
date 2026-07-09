package matrix

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func resetTestDB() {
	if dbInstance != nil {
		_ = dbInstance.Close()
	}
	dbInstance = nil
	dbMu = sync.Mutex{}
}

func TestDatabaseOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fire_starter.db")

	resetTestDB()

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
	err = LogVulnerability("vid-1", "target1.com-updated", "Refined SQL Injection", "poc-1-updated", "yes", "yes")
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
		finding     string
		testCode    string
		exploitable string
		processed   string
		status      string
	}{
		"target1.com-updated": {finding: "Refined SQL Injection", testCode: "poc-1-updated", exploitable: "yes", processed: "yes", status: VulnerabilityStatusConfirmed},
		"target2.com":         {finding: "Cross-Site Scripting", testCode: "poc-2", exploitable: "yes", processed: "yes", status: VulnerabilityStatusConfirmed},
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
		if v.Status != expected.status {
			t.Errorf("Expected status %q for target %s, got %q", expected.status, v.TargetDomain, v.Status)
		}
	}
}

func TestLogVulnerabilityWithStatusRejectsInvalidStatus(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fire_starter.db")

	resetTestDB()
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	err = LogVulnerabilityWithStatus("vid-invalid", "target.com", "Invalid status finding", "poc", "no", "yes", "unknown")
	if err == nil {
		t.Fatalf("expected invalid status to be rejected")
	}

	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected invalid status row not to persist, got %#v", vulns)
	}
}

func TestInitDBMigratesLegacyVulnerabilityStatuses(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_fire_starter.db")

	legacyDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open legacy DB: %v", err)
	}
	_, err = legacyDB.Exec(`
		CREATE TABLE vuln (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id TEXT UNIQUE,
			date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			target_domain TEXT NOT NULL,
			finding TEXT NOT NULL,
			test_code TEXT NOT NULL,
			exploitable TEXT NOT NULL DEFAULT 'no',
			processed TEXT NOT NULL DEFAULT 'no'
		);
		INSERT INTO vuln (vuln_id, target_domain, finding, test_code, exploitable, processed)
		VALUES
			('confirmed-id', 'target1.com', 'Confirmed legacy finding', 'poc', 'yes', 'yes'),
			('candidate-id', 'target2.com', 'Candidate legacy finding', 'poc', 'no', 'no');
	`)
	if err != nil {
		t.Fatalf("failed to create legacy schema: %v", err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatalf("failed to close legacy DB: %v", err)
	}

	resetTestDB()
	_, err = InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}

	statuses := map[string]string{}
	for _, v := range vulns {
		statuses[v.VulnID] = v.Status
	}
	if statuses["confirmed-id"] != VulnerabilityStatusConfirmed {
		t.Fatalf("expected confirmed legacy row to migrate to %q, got %q", VulnerabilityStatusConfirmed, statuses["confirmed-id"])
	}
	if statuses["candidate-id"] != VulnerabilityStatusCandidate {
		t.Fatalf("expected candidate legacy row to remain %q, got %q", VulnerabilityStatusCandidate, statuses["candidate-id"])
	}
}
