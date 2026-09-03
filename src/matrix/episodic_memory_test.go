package matrix_test

import (
	"testing"
	"time"

	"fire_starter/src/matrix"
)

func TestEpisodicMemory_StoreAndQuery(t *testing.T) {
	mem := matrix.NewEpisodicMemory()

	mem.Store(matrix.MemoryEntry{
		ID:        "mem-1",
		Content:   "Discovered endpoint /api/v1/users returning HTTP 200 with SQL database headers",
		Source:    "recon",
		Timestamp: time.Now(),
	})

	mem.Store(matrix.MemoryEntry{
		ID:        "mem-2",
		Content:   "Found port 80 open on host 192.168.1.1 running NGINX web server",
		Source:    "recon",
		Timestamp: time.Now(),
	})

	mem.Store(matrix.MemoryEntry{
		ID:        "mem-3",
		Content:   "Vulnerability confirmed: SQL Injection on parameter id in /api/v1/users",
		Source:    "verifier",
		Timestamp: time.Now(),
	})

	if count := mem.Count(); count != 3 {
		t.Fatalf("expected 3 entries in memory, got %d", count)
	}

	results := mem.Query("SQL injection database", 2)
	if len(results) == 0 {
		t.Fatalf("expected memory query results for 'SQL injection database'")
	}

	if results[0].Entry.ID != "mem-3" && results[0].Entry.ID != "mem-1" {
		t.Errorf("expected top result to be relevant SQL entry, got %s", results[0].Entry.ID)
	}
}
