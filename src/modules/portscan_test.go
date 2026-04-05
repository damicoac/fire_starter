package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPortScanner_Execute(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	scanner := NewPortScanner("127.0.0.1", []int{port, port + 1, port + 2})
	scanner.SetTimeout(100 * time.Millisecond)

	ctx := context.Background()

	// Scan just executes the scan and populates results internally, then returns nil, nil
	// (or partial results and error on cancellation).
	// We need to fetch the results from scanner.getPartialResults() since the return values of Scan
	// are not directly the results slice unless there is a cancellation, wait, looking at the code...
	// Ah, it returns `nil, nil` on success, and updates its internal map `ps.results` but the map value is not exposed.
	// Wait, let's use getPartialResults since it returns the slice.

	_, err = scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	results := scanner.getPartialResults()

	found := false
	for _, res := range results {
		if res.Port == port && res.State == "open" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find port %d open, got results: %+v", port, results)
	}
}
