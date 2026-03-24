package core

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const defaultReinforcementDatabasePath = "blackwater_reinforcement.db"

type ReinforcementLearner interface {
	RecordTransition(ctx context.Context, previousStage string, currentStage string, reward int) error
	RankNextStages(ctx context.Context, previousStage string, candidates []string) ([]string, error)
	Close() error
}

type TransitionStats struct {
	PreviousStage string
	CurrentStage  string
	TotalReward   int
	Attempts      int
	Successes     int
	Failures      int
}

type SQLiteReinforcementLearner struct {
	db *sql.DB
}

func NewSQLiteReinforcementLearner(databasePath string) (*SQLiteReinforcementLearner, error) {
	path := strings.TrimSpace(databasePath)
	if path == "" {
		path = defaultReinforcementDatabasePath
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open reinforcement database: %w", err)
	}

	learner := &SQLiteReinforcementLearner{db: db}
	if err := learner.initializeSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return learner, nil
}

func (l *SQLiteReinforcementLearner) initializeSchema(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS reinforcement_transition_events (
			id INTEGER PRIMARY KEY,
			previous_stage TEXT NOT NULL,
			current_stage TEXT NOT NULL,
			reward INTEGER NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS reinforcement_transition_scores (
			previous_stage TEXT NOT NULL,
			current_stage TEXT NOT NULL,
			total_reward INTEGER NOT NULL DEFAULT 0,
			attempts INTEGER NOT NULL DEFAULT 0,
			successes INTEGER NOT NULL DEFAULT 0,
			failures INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (previous_stage, current_stage)
		)`,
	}

	for _, statement := range schema {
		if _, err := l.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize reinforcement schema: %w", err)
		}
	}

	return nil
}

func (l *SQLiteReinforcementLearner) RecordTransition(ctx context.Context, previousStage string, currentStage string, reward int) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("reinforcement learner is not initialized")
	}
	if strings.TrimSpace(previousStage) == "" {
		return fmt.Errorf("previous stage is required")
	}
	if strings.TrimSpace(currentStage) == "" {
		return fmt.Errorf("current stage is required")
	}

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reinforcement transaction: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO reinforcement_transition_events (previous_stage, current_stage, reward, created_at)
		 VALUES (?, ?, ?, ?)`,
		previousStage,
		currentStage,
		reward,
		now,
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insert reinforcement event: %w", err)
	}

	successes := 0
	failures := 0
	if reward > 0 {
		successes = 1
	} else if reward < 0 {
		failures = 1
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO reinforcement_transition_scores (
			previous_stage,
			current_stage,
			total_reward,
			attempts,
			successes,
			failures,
			updated_at
		 ) VALUES (?, ?, ?, 1, ?, ?, ?)
		 ON CONFLICT(previous_stage, current_stage)
		 DO UPDATE SET
			total_reward = total_reward + excluded.total_reward,
			attempts = attempts + 1,
			successes = successes + excluded.successes,
			failures = failures + excluded.failures,
			updated_at = excluded.updated_at`,
		previousStage,
		currentStage,
		reward,
		successes,
		failures,
		now,
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("upsert reinforcement score: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reinforcement transaction: %w", err)
	}
	return nil
}

func (l *SQLiteReinforcementLearner) RankNextStages(ctx context.Context, previousStage string, candidates []string) ([]string, error) {
	if l == nil || l.db == nil {
		return append([]string(nil), candidates...), nil
	}
	if strings.TrimSpace(previousStage) == "" || len(candidates) == 0 {
		return append([]string(nil), candidates...), nil
	}

	statsByCandidate, err := l.lookupTransitionStats(ctx, previousStage, candidates)
	if err != nil {
		return nil, err
	}

	ranked := append([]string(nil), candidates...)
	sort.SliceStable(ranked, func(i int, j int) bool {
		left := statsByCandidate[ranked[i]]
		right := statsByCandidate[ranked[j]]
		if left.Attempts == 0 && right.Attempts == 0 {
			return false
		}
		if left.Attempts == 0 {
			return false
		}
		if right.Attempts == 0 {
			return true
		}

		leftSuccessRate := float64(left.Successes) / float64(left.Attempts)
		rightSuccessRate := float64(right.Successes) / float64(right.Attempts)
		if leftSuccessRate != rightSuccessRate {
			return leftSuccessRate > rightSuccessRate
		}
		if left.TotalReward != right.TotalReward {
			return left.TotalReward > right.TotalReward
		}
		if left.Attempts != right.Attempts {
			return left.Attempts > right.Attempts
		}
		return ranked[i] < ranked[j]
	})

	return ranked, nil
}

func (l *SQLiteReinforcementLearner) LookupTransitionStats(ctx context.Context, previousStage string, candidates []string) (map[string]TransitionStats, error) {
	return l.lookupTransitionStats(ctx, previousStage, candidates)
}

func (l *SQLiteReinforcementLearner) lookupTransitionStats(ctx context.Context, previousStage string, candidates []string) (map[string]TransitionStats, error) {
	stats := map[string]TransitionStats{}
	for _, candidate := range candidates {
		stats[candidate] = TransitionStats{PreviousStage: previousStage, CurrentStage: candidate}
	}

	placeholders := make([]string, len(candidates))
	args := make([]any, 0, len(candidates)+1)
	args = append(args, previousStage)
	for i, candidate := range candidates {
		placeholders[i] = "?"
		args = append(args, candidate)
	}

	query := `SELECT previous_stage, current_stage, total_reward, attempts, successes, failures
		FROM reinforcement_transition_scores
		WHERE previous_stage = ? AND current_stage IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query reinforcement stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row TransitionStats
		if err := rows.Scan(&row.PreviousStage, &row.CurrentStage, &row.TotalReward, &row.Attempts, &row.Successes, &row.Failures); err != nil {
			return nil, fmt.Errorf("scan reinforcement stats: %w", err)
		}
		stats[row.CurrentStage] = row
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reinforcement stats: %w", err)
	}

	return stats, nil
}

func (l *SQLiteReinforcementLearner) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}
