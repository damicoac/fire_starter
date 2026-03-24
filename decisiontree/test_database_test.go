package decisiontree

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// testRecordCount captures seeded row counts by table.
type testRecordCount struct {
	targets  int
	scans    int
	findings int
}

// createSeededTestDatabase builds an isolated in-memory sqlite database with
// deterministic dummy data that tests can query without external dependencies.
func createSeededTestDatabase(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", "file:testinfra?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	schema := []string{
		`CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			asset_type TEXT NOT NULL,
			environment TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY,
			target_id INTEGER NOT NULL,
			stage TEXT NOT NULL,
			status TEXT NOT NULL,
			run_at TEXT NOT NULL,
			FOREIGN KEY(target_id) REFERENCES targets(id)
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY,
			scan_id INTEGER NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			status TEXT NOT NULL,
			FOREIGN KEY(scan_id) REFERENCES scans(id)
		)`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("apply schema statement %q: %v", stmt, err)
		}
	}

	now := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)

	seedStatements := []string{
		fmt.Sprintf(`INSERT INTO targets (id, name, asset_type, environment, created_at) VALUES
			(1, 'payments-api', 'api', 'staging', '%s'),
			(2, 'backoffice-web', 'web', 'production', '%s')`, now, now),
		fmt.Sprintf(`INSERT INTO scans (id, target_id, stage, status, run_at) VALUES
			(1, 1, 'api-testing.recon', 'complete', '%s'),
			(2, 1, 'api-testing.injection', 'complete', '%s'),
			(3, 2, 'active-testing.access-control', 'running', '%s')`, now, now, now),
		`INSERT INTO findings (id, scan_id, severity, title, status) VALUES
			(1, 2, 'high', 'SQL injection in search endpoint', 'open'),
			(2, 2, 'medium', 'Missing rate-limit on password reset', 'triaged'),
			(3, 3, 'low', 'Verbose error messages expose framework', 'open')`,
	}

	for _, stmt := range seedStatements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed database statement %q: %v", stmt, err)
		}
	}

	return db
}

// loadSeedRecordCounts verifies that the seeded fixtures are visible to queries.
func loadSeedRecordCounts(ctx context.Context, db *sql.DB) (testRecordCount, error) {
	if db == nil {
		return testRecordCount{}, fmt.Errorf("database is required")
	}

	counts := testRecordCount{}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets`).Scan(&counts.targets); err != nil {
		return testRecordCount{}, fmt.Errorf("count targets: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&counts.scans); err != nil {
		return testRecordCount{}, fmt.Errorf("count scans: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&counts.findings); err != nil {
		return testRecordCount{}, fmt.Errorf("count findings: %w", err)
	}

	return counts, nil
}

func TestCreateSeededTestDatabase(t *testing.T) {
	db := createSeededTestDatabase(t)

	counts, err := loadSeedRecordCounts(context.Background(), db)
	if err != nil {
		t.Fatalf("load seed counts: %v", err)
	}

	if counts.targets != 2 {
		t.Fatalf("expected 2 targets, got %d", counts.targets)
	}
	if counts.scans != 3 {
		t.Fatalf("expected 3 scans, got %d", counts.scans)
	}
	if counts.findings != 3 {
		t.Fatalf("expected 3 findings, got %d", counts.findings)
	}
}
