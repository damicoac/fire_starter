package matrix

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	_ "github.com/mattn/go-sqlite3"
)

var (
	dbInstance *sql.DB
	dbMu       sync.RWMutex
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

	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Warnf("SQLite PRAGMA journal_mode=WAL failed: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		log.Warnf("SQLite PRAGMA busy_timeout=5000 failed: %v", err)
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL;"); err != nil {
		log.Warnf("SQLite PRAGMA synchronous=NORMAL failed: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

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

	// Create target_state table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS target_state (
			target_domain TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			current_phase TEXT NOT NULL,
			score INTEGER NOT NULL DEFAULT 0,
			open_ports TEXT NOT NULL DEFAULT '',
			tokens TEXT NOT NULL DEFAULT '',
			last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create target_state table: %w", err)
	}

	// Create executed_payloads table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS executed_payloads (
			payload_hash TEXT PRIMARY KEY,
			tool_name TEXT NOT NULL,
			target TEXT NOT NULL,
			executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create executed_payloads table: %w", err)
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
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_vuln_target ON vuln(target_domain);`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_vuln_status ON vuln(status);`)

	dbInstance = db
	return dbInstance, nil
}

// CloseDB closes the SQLite database connection if one is open.
func CloseDB() error {
	dbMu.Lock()
	defer dbMu.Unlock()

	if dbInstance != nil {
		err := dbInstance.Close()
		dbInstance = nil
		return err
	}
	return nil
}

func getDB() (*sql.DB, error) {
	dbMu.RLock()
	defer dbMu.RUnlock()

	if dbInstance == nil {
		return nil, fmt.Errorf("database not initialized")
	}
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
	db, err := getDB()
	if err != nil {
		return err
	}

	_, err = db.Exec(
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
	db, err := getDB()
	if err != nil {
		return err
	}
	if !IsValidVulnerabilityStatus(status) {
		return fmt.Errorf("invalid vulnerability status: %s", status)
	}
	if !IsValidVulnerabilitySeverity(severity) {
		return fmt.Errorf("invalid vulnerability severity: %s", severity)
	}

	_, err = db.Exec(
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
	db, err := getDB()
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE vuln SET status = 'disproven', severity = 'unknown' WHERE vuln_id = ?", vulnID)
	return err
}


func scanVulnRows(rows *sql.Rows) ([]VulnInfo, error) {
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return vulns, nil
}

// GetVulnerabilities retrieves all vulnerability findings from the database
func GetVulnerabilities() ([]VulnInfo, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}

	rows, err := db.Query("SELECT id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity FROM vuln")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanVulnRows(rows)
}

// GetVulnerabilitiesByTarget retrieves vulnerability findings filtered by a specific target domain
func GetVulnerabilitiesByTarget(targetDomain string) ([]VulnInfo, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}
	normalized := NormalizeURL(targetDomain)
	rows, err := db.Query(
		"SELECT id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity FROM vuln WHERE target_domain = ? OR target_domain = ?",
		normalized, targetDomain,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanVulnRows(rows)
}

// GetVulnerabilitiesPaginated retrieves vulnerability findings with limit and offset
func GetVulnerabilitiesPaginated(limit, offset int) ([]VulnInfo, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.Query(
		"SELECT id, vuln_id, date_time, target_domain, finding, test_code, exploitable, status, severity FROM vuln ORDER BY id ASC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanVulnRows(rows)
}

// IsPayloadExecuted checks if a specific tool payload hash was already executed
func IsPayloadExecuted(payloadHash string) (bool, error) {
	db, err := getDB()
	if err != nil {
		return false, nil
	}
	var count int
	err = db.QueryRow("SELECT COUNT(1) FROM executed_payloads WHERE payload_hash = ?", payloadHash).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// RecordPayloadExecuted records a tool execution hash in the database
func RecordPayloadExecuted(payloadHash, toolName, target string) error {
	db, err := getDB()
	if err != nil {
		return nil
	}
	_, err = db.Exec(
		`INSERT OR IGNORE INTO executed_payloads (payload_hash, tool_name, target, executed_at) VALUES (?, ?, ?, ?)`,
		payloadHash, toolName, target, time.Now().UTC(),
	)
	return err
}

type StoredTargetState struct {
	TargetDomain string
	Type         string
	CurrentPhase string
	Score        int
	OpenPorts    []int
	Tokens       []string
}

// SaveTargetState persists target metadata and lifecycle phase to SQLite
func SaveTargetState(targetDomain, targetType, currentPhase string, score int, openPorts []int, tokens []string) error {
	db, err := getDB()
	if err != nil {
		return err
	}
	portsBytes, _ := json.Marshal(openPorts)
	tokensBytes, _ := json.Marshal(tokens)
	_, err = db.Exec(
		`INSERT INTO target_state (target_domain, type, current_phase, score, open_ports, tokens, last_updated)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(target_domain) DO UPDATE SET
			type = excluded.type,
			current_phase = excluded.current_phase,
			score = excluded.score,
			open_ports = excluded.open_ports,
			tokens = excluded.tokens,
			last_updated = excluded.last_updated`,
		targetDomain, targetType, currentPhase, score, string(portsBytes), string(tokensBytes), time.Now().UTC(),
	)
	return err
}

// LoadTargetStates loads all persisted target states from SQLite
func LoadTargetStates() ([]StoredTargetState, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT target_domain, type, current_phase, score, open_ports, tokens FROM target_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var states []StoredTargetState
	for rows.Next() {
		var s StoredTargetState
		var portsStr, tokensStr string
		if err := rows.Scan(&s.TargetDomain, &s.Type, &s.CurrentPhase, &s.Score, &portsStr, &tokensStr); err != nil {
			return nil, err
		}
		if portsStr != "" {
			_ = json.Unmarshal([]byte(portsStr), &s.OpenPorts)
		}
		if tokensStr != "" {
			_ = json.Unmarshal([]byte(tokensStr), &s.Tokens)
		}
		states = append(states, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return states, nil
}
