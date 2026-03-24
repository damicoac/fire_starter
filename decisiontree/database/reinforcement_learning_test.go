// File overview:
// Test coverage for this module. These tests exist to lock expected behavior and prevent regressions in stage routing, payload handling, and integration boundaries.

package decisiontree

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewSQLiteReinforcementLearner_CreatesDatabaseAndSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reinforcement.sqlite")
	learner, err := NewSQLiteReinforcementLearner(dbPath)
	if err != nil {
		t.Fatalf("create reinforcement learner: %v", err)
	}
	t.Cleanup(func() {
		_ = learner.Close()
	})

	_, err = learner.LookupTransitionStats(context.Background(), "stage.a", []string{"stage.b"})
	if err != nil {
		t.Fatalf("expected schema to be initialized, got lookup error: %v", err)
	}
}

func TestSQLiteReinforcementLearner_RecordTransitionAndRankNextStages(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reinforcement.sqlite")
	learner, err := NewSQLiteReinforcementLearner(dbPath)
	if err != nil {
		t.Fatalf("create reinforcement learner: %v", err)
	}
	t.Cleanup(func() {
		_ = learner.Close()
	})

	ctx := context.Background()
	if err := learner.RecordTransition(ctx, "target.received", "api-testing.recon", 1); err != nil {
		t.Fatalf("record positive transition: %v", err)
	}
	if err := learner.RecordTransition(ctx, "target.received", "api-testing.recon", 1); err != nil {
		t.Fatalf("record second positive transition: %v", err)
	}
	if err := learner.RecordTransition(ctx, "target.received", "application-mapping.explore", -1); err != nil {
		t.Fatalf("record negative transition: %v", err)
	}
	if err := learner.RecordTransition(ctx, "target.received", "application-mapping.explore", 1); err != nil {
		t.Fatalf("record mixed transition: %v", err)
	}

	ranked, err := learner.RankNextStages(ctx, "target.received", []string{"application-mapping.explore", "api-testing.recon", "active-testing.access-control"})
	if err != nil {
		t.Fatalf("rank stages: %v", err)
	}

	expected := []string{"api-testing.recon", "application-mapping.explore", "active-testing.access-control"}
	if !reflect.DeepEqual(ranked, expected) {
		t.Fatalf("expected ranking %v, got %v", expected, ranked)
	}

	stats, err := learner.LookupTransitionStats(ctx, "target.received", []string{"api-testing.recon", "application-mapping.explore"})
	if err != nil {
		t.Fatalf("lookup stats: %v", err)
	}
	apiStats := stats["api-testing.recon"]
	if apiStats.Attempts != 2 || apiStats.Successes != 2 || apiStats.Failures != 0 || apiStats.TotalReward != 2 {
		t.Fatalf("unexpected api-testing stats: %#v", apiStats)
	}
	mappingStats := stats["application-mapping.explore"]
	if mappingStats.Attempts != 2 || mappingStats.Successes != 1 || mappingStats.Failures != 1 || mappingStats.TotalReward != 0 {
		t.Fatalf("unexpected application-mapping stats: %#v", mappingStats)
	}
}

func TestSQLiteReinforcementLearner_RecordTransitionValidation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reinforcement.sqlite")
	learner, err := NewSQLiteReinforcementLearner(dbPath)
	if err != nil {
		t.Fatalf("create reinforcement learner: %v", err)
	}
	t.Cleanup(func() {
		_ = learner.Close()
	})

	ctx := context.Background()
	if err := learner.RecordTransition(ctx, "", "stage.b", 1); err == nil {
		t.Fatalf("expected previous stage validation error")
	}
	if err := learner.RecordTransition(ctx, "stage.a", "", -1); err == nil {
		t.Fatalf("expected current stage validation error")
	}
}
