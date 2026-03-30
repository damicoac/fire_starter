package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const defaultAuditDatabasePath = "blackwater_audit.db"

type AuditLogger interface {
	LogAction(ctx context.Context, event AuditEvent) error
	Close() error
}

type AuditEvent struct {
	RunID     string
	Sequence  int
	Mode      string
	Action    string
	Stage     string
	ToolName  string
	Status    string
	Details   map[string]any
	CreatedAt string
}

type SQLiteAuditLogger struct {
	db *sql.DB
}

func NewSQLiteAuditLogger(databasePath string) (*SQLiteAuditLogger, error) {
	path := strings.TrimSpace(databasePath)
	if path == "" {
		path = defaultAuditDatabasePath
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit database: %w", err)
	}

	logger := &SQLiteAuditLogger{db: db}
	if err := logger.initializeSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return logger, nil
}

func (l *SQLiteAuditLogger) initializeSchema(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY,
			run_id TEXT NOT NULL,
			sequence INTEGER NOT NULL,
			mode TEXT NOT NULL,
			action TEXT NOT NULL,
			stage TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			status TEXT NOT NULL,
			details_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(run_id, sequence)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_run_sequence
			ON audit_events(run_id, sequence)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
			ON audit_events(created_at)`,
	}

	for _, statement := range schema {
		if _, err := l.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize audit schema: %w", err)
		}
	}

	return nil
}

func (l *SQLiteAuditLogger) LogAction(ctx context.Context, event AuditEvent) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("audit logger is not initialized")
	}
	if strings.TrimSpace(event.RunID) == "" {
		return fmt.Errorf("audit run id is required")
	}
	if event.Sequence <= 0 {
		return fmt.Errorf("audit sequence must be positive")
	}
	if strings.TrimSpace(event.Mode) == "" {
		return fmt.Errorf("audit mode is required")
	}
	if strings.TrimSpace(event.Action) == "" {
		return fmt.Errorf("audit action is required")
	}
	if strings.TrimSpace(event.Status) == "" {
		return fmt.Errorf("audit status is required")
	}

	createdAt := strings.TrimSpace(event.CreatedAt)
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	details := event.Details
	if details == nil {
		details = map[string]any{}
	}
	encodedDetails, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}

	_, err = l.db.ExecContext(
		ctx,
		`INSERT INTO audit_events (
			run_id,
			sequence,
			mode,
			action,
			stage,
			tool_name,
			status,
			details_json,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.RunID,
		event.Sequence,
		event.Mode,
		event.Action,
		event.Stage,
		event.ToolName,
		event.Status,
		string(encodedDetails),
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}

func (l *SQLiteAuditLogger) LookupAuditEvents(ctx context.Context, runID string) ([]AuditEvent, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("audit logger is not initialized")
	}
	if strings.TrimSpace(runID) == "" {
		return nil, fmt.Errorf("audit run id is required")
	}

	rows, err := l.db.QueryContext(
		ctx,
		`SELECT run_id, sequence, mode, action, stage, tool_name, status, details_json, created_at
		 FROM audit_events
		 WHERE run_id = ?
		 ORDER BY sequence ASC`,
		runID,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	events := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var detailsJSON string
		if err := rows.Scan(
			&event.RunID,
			&event.Sequence,
			&event.Mode,
			&event.Action,
			&event.Stage,
			&event.ToolName,
			&event.Status,
			&detailsJSON,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if err := json.Unmarshal([]byte(detailsJSON), &event.Details); err != nil {
			return nil, fmt.Errorf("unmarshal audit details: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return events, nil
}

func (l *SQLiteAuditLogger) ListRunIDs(ctx context.Context) ([]string, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("audit logger is not initialized")
	}

	rows, err := l.db.QueryContext(ctx, `SELECT run_id FROM audit_events GROUP BY run_id ORDER BY MAX(id) DESC`)
	if err != nil {
		return nil, fmt.Errorf("query audit run ids: %w", err)
	}
	defer rows.Close()

	runIDs := make([]string, 0)
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			return nil, fmt.Errorf("scan audit run id: %w", err)
		}
		runIDs = append(runIDs, runID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit run ids: %w", err)
	}

	return runIDs, nil
}

func (l *SQLiteAuditLogger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}
