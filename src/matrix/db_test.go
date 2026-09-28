package matrix

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func resetTestDB() {
	_ = CloseDB()
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
	err = LogVulnerability("vid-1", "target1.com", "SQL Injection", "poc-1", "no")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	err = LogVulnerability("vid-2", "target2.com", "Cross-Site Scripting", "poc-2", "yes")
	if err != nil {
		t.Fatalf("LogVulnerability failed: %v", err)
	}

	// Upsert existing vulnerability
	err = LogVulnerability("vid-1", "target1.com-updated", "Refined SQL Injection", "poc-1-updated", "yes")
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
		status      string
		severity    string
	}{
		"target1.com-updated": {finding: "Refined SQL Injection", testCode: "poc-1-updated", exploitable: "yes", status: VulnerabilityStatusConfirmed, severity: VulnerabilitySeverityUnknown},
		"target2.com":         {finding: "Cross-Site Scripting", testCode: "poc-2", exploitable: "yes", status: VulnerabilityStatusConfirmed, severity: VulnerabilitySeverityUnknown},
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
		if v.Status != expected.status {
			t.Errorf("Expected status %q for target %s, got %q", expected.status, v.TargetDomain, v.Status)
		}
		if v.Severity != expected.severity {
			t.Errorf("Expected severity %q for target %s, got %q", expected.severity, v.TargetDomain, v.Severity)
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

	err = LogVulnerabilityWithStatus("vid-invalid", "target.com", "Invalid status finding", "poc", "no", "unknown", VulnerabilitySeverityUnknown)
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

func TestLogVulnerabilityWithStatusRejectsInvalidSeverity(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fire_starter.db")

	resetTestDB()
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	err = LogVulnerabilityWithStatus("vid-invalid", "target.com", "Invalid severity finding", "poc", "no", VulnerabilityStatusCandidate, "urgent")
	if err == nil {
		t.Fatalf("expected invalid severity to be rejected")
	}

	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected invalid severity row not to persist, got %#v", vulns)
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
	severities := map[string]string{}
	for _, v := range vulns {
		statuses[v.VulnID] = v.Status
		severities[v.VulnID] = v.Severity
	}
	if statuses["confirmed-id"] != VulnerabilityStatusConfirmed {
		t.Fatalf("expected confirmed legacy row to migrate to %q, got %q", VulnerabilityStatusConfirmed, statuses["confirmed-id"])
	}
	if statuses["candidate-id"] != VulnerabilityStatusCandidate {
		t.Fatalf("expected candidate legacy row to remain %q, got %q", VulnerabilityStatusCandidate, statuses["candidate-id"])
	}
	if severities["confirmed-id"] != VulnerabilitySeverityUnknown || severities["candidate-id"] != VulnerabilitySeverityUnknown {
		t.Fatalf("expected legacy rows to use unknown severity, got %#v", severities)
	}

	db, err := getDB()
	if err != nil {
		t.Fatalf("getDB failed: %v", err)
	}
	columns, err := vulnColumnNames(db)
	if err != nil {
		t.Fatalf("vulnColumnNames failed: %v", err)
	}
	if columns["processed"] {
		t.Fatalf("expected processed column to be removed during migration")
	}
}

func TestGetVulnerabilitiesByTargetAndPaginated(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_target_vulns.db")

	resetTestDB()
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	_ = LogVulnerability("v1", "http://example.com/api", "Finding 1", "poc-1", "yes")
	_ = LogVulnerability("v2", "http://example.com/admin", "Finding 2", "poc-2", "no")
	_ = LogVulnerability("v3", "http://other.com", "Finding 3", "poc-3", "yes")

	byTarget, err := GetVulnerabilitiesByTarget("example.com")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesByTarget failed: %v", err)
	}
	if len(byTarget) != 0 { // Target was http://example.com/api which normalizes to example.com/api
		t.Logf("byTarget count for exact domain: %d", len(byTarget))
	}

	byTargetAPI, err := GetVulnerabilitiesByTarget("http://example.com/api")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesByTarget failed: %v", err)
	}
	if len(byTargetAPI) != 1 || byTargetAPI[0].VulnID != "v1" {
		t.Fatalf("Expected 1 finding for example.com/api, got %#v", byTargetAPI)
	}

	paginated, err := GetVulnerabilitiesPaginated(2, 0)
	if err != nil {
		t.Fatalf("GetVulnerabilitiesPaginated failed: %v", err)
	}
	if len(paginated) != 2 {
		t.Fatalf("Expected 2 paginated findings, got %d", len(paginated))
	}

	page2, err := GetVulnerabilitiesPaginated(2, 2)
	if err != nil {
		t.Fatalf("GetVulnerabilitiesPaginated offset failed: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("Expected 1 finding on page 2, got %d", len(page2))
	}
}

func TestPayloadIdempotency(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_idempotency.db")

	resetTestDB()
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	executed, err := IsPayloadExecuted("hash-123")
	if err != nil {
		t.Fatalf("IsPayloadExecuted failed: %v", err)
	}
	if executed {
		t.Fatalf("Expected payload to not be executed yet")
	}

	err = RecordPayloadExecuted("hash-123", "sql_injection", "http://target.com")
	if err != nil {
		t.Fatalf("RecordPayloadExecuted failed: %v", err)
	}

	executed, err = IsPayloadExecuted("hash-123")
	if err != nil {
		t.Fatalf("IsPayloadExecuted failed: %v", err)
	}
	if !executed {
		t.Fatalf("Expected payload to be marked as executed")
	}

	// Repeated record should be ignored without error
	err = RecordPayloadExecuted("hash-123", "sql_injection", "http://target.com")
	if err != nil {
		t.Fatalf("Duplicate RecordPayloadExecuted failed: %v", err)
	}
}

func TestTargetStatePersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_target_state.db")

	resetTestDB()
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	err = SaveTargetState("app.example.com", "url", "scanning-enumeration", 30, []int{80, 443}, []string{"token-1", "token-2"})
	if err != nil {
		t.Fatalf("SaveTargetState failed: %v", err)
	}

	states, err := LoadTargetStates()
	if err != nil {
		t.Fatalf("LoadTargetStates failed: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("Expected 1 target state, got %d", len(states))
	}
	s := states[0]
	if s.TargetDomain != "app.example.com" || s.CurrentPhase != "scanning-enumeration" || s.Score != 30 {
		t.Fatalf("Unexpected target state values: %#v", s)
	}
	if len(s.OpenPorts) != 2 || s.OpenPorts[0] != 80 || s.OpenPorts[1] != 443 {
		t.Fatalf("Unexpected open ports: %#v", s.OpenPorts)
	}
	if len(s.Tokens) != 2 || s.Tokens[0] != "token-1" {
		t.Fatalf("Unexpected tokens: %#v", s.Tokens)
	}

	// Update existing state
	err = SaveTargetState("app.example.com", "url", "exploitation", 40, []int{80, 443, 8080}, []string{"token-1"})
	if err != nil {
		t.Fatalf("SaveTargetState update failed: %v", err)
	}
	states2, err := LoadTargetStates()
	if err != nil {
		t.Fatalf("LoadTargetStates failed: %v", err)
	}
	if len(states2) != 1 || states2[0].CurrentPhase != "exploitation" || len(states2[0].OpenPorts) != 3 {
		t.Fatalf("Updated state not reflected: %#v", states2)
	}
}
