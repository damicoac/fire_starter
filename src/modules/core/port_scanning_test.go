package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPortScanning_Execute_OpenPort(t *testing.T) {
	module := NewPortScanning("http://example.com")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return []portResult{
			{Port: 80, State: "open", Banner: "nginx"},
			{Port: 22, State: "closed"},
		}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 result for the open port, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected status %q for an open-port finding, got %q", "inconclusive", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "Port 80 is open") {
		t.Errorf("Expected detail to describe the open port, got %q", result[0].Detail)
	}
}

func TestPortScanning_Execute_AllClosedSecure(t *testing.T) {
	module := NewPortScanning("http://example.com")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return []portResult{
			{Port: 80, State: "closed"},
			{Port: 443, State: "closed"},
		}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 summary result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "secure" {
		t.Errorf("Expected status %q when all ports are closed, got %q", "secure", result[0].Status)
	}
}

func TestPortScanning_Execute_AllDialsErrored(t *testing.T) {
	module := NewPortScanning("http://dead-host.invalid")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return []portResult{
			{Port: 80, State: "filtered"},
			{Port: 443, State: "filtered"},
		}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// A dead host must not be reported as silently clean.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive result for a dead host, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected status %q when every dial errored, got %q", "inconclusive", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "errored") {
		t.Errorf("Expected detail to mention dial failures, got %q", result[0].Detail)
	}
}

func TestPortScanning_Execute_MixedClosedAndFilteredInconclusive(t *testing.T) {
	module := NewPortScanning("http://example.com")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return []portResult{
			{Port: 80, State: "closed"},
			{Port: 443, State: "closed"},
			{Port: 22, State: "filtered"},
		}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Filtered dials leave those ports unverified: the "all ports closed"
	// secure summary must not fire while any dial attempt errored.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 summary result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected inconclusive while filtered ports remain unverified, got %q", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "unverified") {
		t.Errorf("Expected detail to name unverified ports, got %q", result[0].Detail)
	}
}

func TestPortScanning_Execute_ScanError(t *testing.T) {
	module := NewPortScanning("http://example.com")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return nil, errors.New("scan exploded")
	}

	_, err := module.Execute(context.Background())
	if err == nil || err.Error() != "scan exploded" {
		t.Fatalf("Expected scan error to propagate, got %v", err)
	}
}

func TestPortScanning_Execute_CanceledContext(t *testing.T) {
	module := NewPortScanning("http://example.com")
	module.scan = func(ctx context.Context) ([]portResult, error) {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := module.Execute(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Expected context.Canceled, got %v", err)
	}
}

func TestScanTargetHost(t *testing.T) {
	cases := []struct {
		target   string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"http://example.com:8080/app", "example.com"},
		{"https://example.com", "example.com"},
		{"http://[::1]:8080/app", "::1"},
		{"http://[::1]/", "::1"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
		{"example.com:8443", "example.com"},
	}

	for _, tc := range cases {
		if got := scanTargetHost(tc.target); got != tc.expected {
			t.Errorf("scanTargetHost(%q) = %q, expected %q", tc.target, got, tc.expected)
		}
	}
}
