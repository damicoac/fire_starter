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
	dbOnce     sync.Once
)

// InitDB initializes the SQLite database connection and creates tables if they don't exist.
func InitDB(dbPath string) (*sql.DB, error) {
	var initErr error
	dbOnce.Do(func() {
		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			initErr = fmt.Errorf("failed to open database: %w", err)
			return
		}

		if err := db.Ping(); err != nil {
			initErr = fmt.Errorf("failed to ping database: %w", err)
			return
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
			initErr = fmt.Errorf("failed to create execution_log table: %w", err)
			return
		}

		// Create vuln table
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS vuln (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
				target_domain TEXT NOT NULL,
				finding TEXT NOT NULL,
				test_code TEXT NOT NULL
			);
		`)
		if err != nil {
			initErr = fmt.Errorf("failed to create vuln table: %w", err)
			return
		}

		dbInstance = db
	})

	if initErr != nil {
		return nil, initErr
	}
	return dbInstance, nil
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
	DateTime     time.Time
	TargetDomain string
	Finding      string
	TestCode     string
}

// LogVulnerability writes a vulnerability finding with its test code to the SQLite database
func LogVulnerability(targetDomain string, finding string, testCode string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := dbInstance.Exec(
		"INSERT INTO vuln (date_time, target_domain, finding, test_code) VALUES (?, ?, ?, ?)",
		time.Now().UTC(), targetDomain, finding, testCode,
	)
	return err
}

// GetVulnerabilities retrieves all vulnerability findings from the database
func GetVulnerabilities() ([]VulnInfo, error) {
	if dbInstance == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := dbInstance.Query("SELECT id, date_time, target_domain, finding, test_code FROM vuln")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []VulnInfo
	for rows.Next() {
		var v VulnInfo
		var dtStr string
		if err := rows.Scan(&v.ID, &dtStr, &v.TargetDomain, &v.Finding, &v.TestCode); err != nil {
			return nil, err
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

