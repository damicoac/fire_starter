package matrix

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	dbInstance *sql.DB
	dbMu       sync.Mutex
)

// InitDB initializes the SQLite database connection and creates tables if they don't exist.
func InitDB(dbPath string) (*sql.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	if dbInstance != nil {
		return dbInstance, nil
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create execution_log table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS execution_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			target_domain TEXT NOT NULL,
			json_output TEXT NOT NULL
		);
	`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create execution_log table: %w", err)
	}

	// Create vuln table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vuln (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id TEXT UNIQUE,
			date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			target_domain TEXT NOT NULL,
			finding TEXT NOT NULL,
			test_code TEXT NOT NULL,
			exploitable TEXT NOT NULL DEFAULT 'no',
			status TEXT NOT NULL DEFAULT 'candidate',
			severity TEXT NOT NULL DEFAULT 'unknown'
		);
	`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create vuln table: %w", err)
	}

	if err := ensureVulnColumn(db, "exploitable", "TEXT NOT NULL DEFAULT 'no'"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureVulnColumn(db, "vuln_id", "TEXT"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureVulnColumn(db, "status", "TEXT NOT NULL DEFAULT 'candidate'"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureVulnColumn(db, "severity", "TEXT NOT NULL DEFAULT 'unknown'"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateVulnerabilityStatuses(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := dropLegacyProcessedColumn(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_id ON vuln(vuln_id);`)
	if err != nil && err.Error() != "index idx_vuln_id already exists" { // SQLite might ignore IF NOT EXISTS depending on version, so just in case
		_ = db.Close()
		return nil, fmt.Errorf("failed to create unique index on vuln_id: %w", err)
	}

	dbInstance = db
	return dbInstance, nil
}

func migrateVulnerabilityStatuses(db *sql.DB) error {
	_, err := db.Exec("UPDATE vuln SET status = 'confirmed' WHERE exploitable = 'yes' AND (status = '' OR status = 'candidate')")
	if err != nil {
		return fmt.Errorf("failed to migrate confirmed vulnerability statuses: %w", err)
	}
	return nil
}

func dropLegacyProcessedColumn(db *sql.DB) error {
	columns, err := vulnColumnNames(db)
	if err != nil {
		return err
	}
	if !columns["processed"] {
		return nil
	}

	_, err = db.Exec(`
		CREATE TABLE vuln_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id TEXT UNIQUE,
			date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			target_domain TEXT NOT NULL,
			finding TEXT NOT NULL,
			test_code TEXT NOT NULL,
			exploitable TEXT NOT NULL DEFAULT 'no',
			status TEXT NOT NULL DEFAULT 'candidate',
			severity TEXT NOT NULL DEFAULT 'unknown'
		);
		INSERT INTO vuln_new (id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity)
		SELECT id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity FROM vuln;
		DROP TABLE vuln;
		ALTER TABLE vuln_new RENAME TO vuln;
	`)
	if err != nil {
		return fmt.Errorf("failed to drop legacy processed column: %w", err)
	}
	return nil
}

func vulnColumnNames(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(vuln)")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect vuln table schema: %w", err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name string
		var colType string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to inspect vuln table schema row: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate vuln table schema rows: %w", err)
	}
	return columns, nil
}

func ensureVulnColumn(db *sql.DB, columnName string, columnDef string) error {
	rows, err := db.Query("PRAGMA table_info(vuln)")
	if err != nil {
		return fmt.Errorf("failed to inspect vuln table schema: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var colType string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("failed to inspect vuln table schema row: %w", err)
		}
		if name == columnName {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iterate vuln table schema rows: %w", err)
	}

	_, err = db.Exec(fmt.Sprintf("ALTER TABLE vuln ADD COLUMN %s %s", columnName, columnDef))
	if err != nil {
		return fmt.Errorf("failed to add %s column to vuln table: %w", columnName, err)
	}
	return nil
}

// LogExecution writes an execution output to the SQLite database
func LogExecution(targetDomain string, jsonOutput string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := dbInstance.Exec(
		"INSERT INTO execution_log (date_time, target_domain, json_output) VALUES (?, ?, ?)",
		time.Now().UTC(), targetDomain, jsonOutput,
	)
	return err
}

// VulnInfo holds vulnerability details retrieved from the database
type VulnInfo struct {
	ID           int
	VulnID       string
	DateTime     time.Time
	TargetDomain string
	Finding      string
	TestCode     string
	Exploitable  string
	Status       string
	Severity     string
}

const (
	VulnerabilityStatusCandidate     = "candidate"
	VulnerabilityStatusConfirmed     = "confirmed"
	VulnerabilityStatusDisproven     = "disproven"
	VulnerabilityStatusInformational = "informational"

	VulnerabilitySeverityCritical      = "critical"
	VulnerabilitySeverityHigh          = "high"
	VulnerabilitySeverityMedium        = "medium"
	VulnerabilitySeverityLow           = "low"
	VulnerabilitySeverityInformational = "informational"
	VulnerabilitySeverityUnknown       = "unknown"
)

func IsValidVulnerabilityStatus(status string) bool {
	switch status {
	case VulnerabilityStatusCandidate, VulnerabilityStatusConfirmed, VulnerabilityStatusDisproven, VulnerabilityStatusInformational:
		return true
	default:
		return false
	}
}

func NormalizeVulnerabilityStatus(status string) string {
	if IsValidVulnerabilityStatus(status) {
		return status
	}
	return VulnerabilityStatusCandidate
}

func IsValidVulnerabilitySeverity(severity string) bool {
	switch severity {
	case VulnerabilitySeverityCritical, VulnerabilitySeverityHigh, VulnerabilitySeverityMedium, VulnerabilitySeverityLow, VulnerabilitySeverityInformational, VulnerabilitySeverityUnknown:
		return true
	default:
		return false
	}
}

func NormalizeVulnerabilitySeverity(severity string) string {
	if IsValidVulnerabilitySeverity(severity) {
		return severity
	}
	return VulnerabilitySeverityUnknown
}

// LogVulnerability writes or updates a vulnerability finding with its test code to the SQLite database
func LogVulnerability(vulnID string, targetDomain string, finding string, testCode string, exploitable string) error {
	status := VulnerabilityStatusCandidate
	severity := VulnerabilitySeverityUnknown
	if exploitable == "yes" {
		status = VulnerabilityStatusConfirmed
	}
	return LogVulnerabilityWithStatus(vulnID, targetDomain, finding, testCode, exploitable, status, severity)
}

func LogVulnerabilityWithStatus(vulnID string, targetDomain string, finding string, testCode string, exploitable string, status string, severity string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}
	if !IsValidVulnerabilityStatus(status) {
		return fmt.Errorf("invalid vulnerability status: %s", status)
	}
	if !IsValidVulnerabilitySeverity(severity) {
		return fmt.Errorf("invalid vulnerability severity: %s", severity)
	}

	_, err := dbInstance.Exec(
		`INSERT INTO vuln (vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vuln_id) DO UPDATE SET 
			date_time = excluded.date_time,
			target_domain = excluded.target_domain,
			finding = excluded.finding,
			test_code = excluded.test_code,
			exploitable = excluded.exploitable,
			status = excluded.status,
			severity = excluded.severity`,
		vulnID, time.Now().UTC(), targetDomain, finding, testCode, exploitable, status, severity,
	)
	return err
}

func MarkVulnerabilityDisproven(vulnID string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := dbInstance.Exec("UPDATE vuln SET status = 'disproven', severity = 'unknown' WHERE vuln_id = ?", vulnID)
	return err
}

// DeleteVulnerability removes a vulnerability from the database
func DeleteVulnerability(vulnID string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := dbInstance.Exec("DELETE FROM vuln WHERE vuln_id = ?", vulnID)
	return err
}

// GetVulnerabilities retrieves all vulnerability findings from the database
func GetVulnerabilities() ([]VulnInfo, error) {
	if dbInstance == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := dbInstance.Query("SELECT id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity FROM vuln")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []VulnInfo
	for rows.Next() {
		var v VulnInfo
		var dtStr string
		var vulnID sql.NullString
		if err := rows.Scan(&v.ID, &vulnID, &dtStr, &v.TargetDomain, &v.Finding, &v.TestCode, &v.Exploitable, &v.Status, &v.Severity); err != nil {
			return nil, err
		}
		v.Status = NormalizeVulnerabilityStatus(v.Status)
		v.Severity = NormalizeVulnerabilitySeverity(v.Severity)
		if vulnID.Valid {
			v.VulnID = vulnID.String
		}

		// Parse date_time string
		if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", dtStr); err == nil {
			v.DateTime = t
		} else if t, err := time.Parse(time.RFC3339, dtStr); err == nil {
			v.DateTime = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", dtStr); err == nil {
			v.DateTime = t
		} else {
			v.DateTime = time.Now()
		}

		vulns = append(vulns, v)
	}
	return vulns, nil
}
