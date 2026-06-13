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

		// Create target_reports table
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS target_reports (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
				target_domain TEXT NOT NULL,
				json_data TEXT NOT NULL
			);
		`)
		if err != nil {
			initErr = fmt.Errorf("failed to create target_reports table: %w", err)
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

// LogTargetReport writes parsed target intelligence to the SQLite database
func LogTargetReport(targetDomain string, jsonData string) error {
	if dbInstance == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := dbInstance.Exec(
		"INSERT INTO target_reports (date_time, target_domain, json_data) VALUES (?, ?, ?)",
		time.Now().UTC(), targetDomain, jsonData,
	)
	return err
}
