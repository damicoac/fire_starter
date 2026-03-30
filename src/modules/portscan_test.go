package modules

import (
	"context"
	"testing"
	"time"
)

func TestNewPortScanner(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", []int{80, 443})

	if scanner.Target != "127.0.0.1" {
		t.Errorf("Expected target 127.0.0.1, got %s", scanner.Target)
	}

	if len(scanner.Ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(scanner.Ports))
	}

	if scanner.Timeout != 2*time.Second {
		t.Errorf("Expected default timeout 2s, got %v", scanner.Timeout)
	}

	if scanner.Threads != 100 {
		t.Errorf("Expected default threads 100, got %d", scanner.Threads)
	}
}

func TestSetTimeout(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", nil)

	scanner.SetTimeout(5 * time.Second)
	if scanner.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", scanner.Timeout)
	}
}

func TestSetPortScanThreads(t *testing.T) {
	scanner := NewPortScanner("127.0.0.1", nil)

	scanner.SetThreads(50)
	if scanner.Threads != 50 {
		t.Errorf("Expected threads 50, got %d", scanner.Threads)
	}

	// Test invalid value (should default to 1)
	scanner.SetThreads(0)
	if scanner.Threads != 1 {
		t.Errorf("Expected threads to default to 1 for invalid value, got %d", scanner.Threads)
	}
}

func TestPortRange(t *testing.T) {
	s := NewPortScanner("127.0.0.1", []int{})
	_, err := s.ScanPortRange(80, 82)
	if err != nil {
		t.Fatalf("ScanPortRange failed: %v", err)
	}

	if len(s.Ports) != 3 {
		t.Errorf("Expected 3 ports in range, got %d", len(s.Ports))
	}
}

func TestScanCommonPorts(t *testing.T) {
	// This is a real scan - skip if running in fast mode
	if testing.Short() {
		t.Skip("skipping real port scan")
	}

	s := NewPortScanner("127.0.0.1", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := s.ScanCommonPorts(ctx)
	if err != nil {
		t.Fatalf("ScanCommonPorts failed: %v", err)
	}
}
