package core

import (
	"context"
	"net"
	"testing"
)

func TestNewPortScanner(t *testing.T) {
	target := "127.0.0.1"
	ports := []int{80, 443}
	scanner := NewPortScanner(target, ports)

	if scanner.Target != target {
		t.Errorf("Expected target %s, got %s", target, scanner.Target)
	}

	if len(scanner.Ports) != len(ports) {
		t.Errorf("Expected %d ports, got %d", len(ports), len(scanner.Ports))
	}
}

func TestSetThreads(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{80})
	scanner.SetThreads(50)

	if scanner.Threads != 50 {
		t.Errorf("Expected 50 threads, got %d", scanner.Threads)
	}

	// Test boundary
	scanner.SetThreads(0)
	if scanner.Threads != 1 {
		t.Errorf("Expected threads to default to 1 when set to <1, got %d", scanner.Threads)
	}
}

func TestPortScanner_Scan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	scanner := NewPortScanner("127.0.0.1", []int{port, port + 1, port + 2})

	ctx := context.Background()

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

func TestPortScanner_Execute_CanceledContext(t *testing.T) {
	scanner := NewPortScanner("example.com", []int{80})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = scanner.Scan(ctx)
}

func TestPortScanner_Execute_InvalidURL(t *testing.T) {
	scanner := NewPortScanner("invalid-url-:foo", []int{80})
	ctx := context.Background()
	_, _ = scanner.Scan(ctx)
}

// TestPortScanner_Scan_ClosedPortRefused pins the closed-vs-filtered semantics:
// an immediate ECONNREFUSED from a reachable host must classify as "closed",
// not as "filtered".
func TestPortScanner_Scan_ClosedPortRefused(t *testing.T) {
	// Grab a port, then release it so nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve listener: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("Failed to release listener: %v", err)
	}

	scanner := NewPortScanner("127.0.0.1", []int{closedPort})
	results, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d: %+v", len(results), results)
	}
	if results[0].State != "closed" {
		t.Errorf("Expected state %q for connection-refused port, got %q", "closed", results[0].State)
	}
}

// TestPortScanner_ScanPort_CancelledContext pins that ports in flight at
// cancellation report a neutral state instead of being recorded as "closed".
func TestPortScanner_ScanPort_CancelledContext(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{59999})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.scanPort(ctx, 59999)
	if result.State != "skipped" {
		t.Errorf("Expected neutral state %q for port in flight at cancellation, got %q", "skipped", result.State)
	}
	if result.Banner != "" {
		t.Errorf("Expected empty banner for a skipped port, got %q", result.Banner)
	}
}
