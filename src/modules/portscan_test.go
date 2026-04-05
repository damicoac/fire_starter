package modules

import (
	"context"
	"net"
	"testing"
	"time"
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

func TestSetTimeout(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{80})
	scanner.SetTimeout(5 * time.Second)

	if scanner.Timeout != 5*time.Second {
		t.Errorf("Expected timeout to be 5s, got %v", scanner.Timeout)
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
	scanner.SetTimeout(100 * time.Millisecond)

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
