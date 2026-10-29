package core

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func newTestSubdomainEnumeration(t *testing.T) *SubdomainEnumeration {
	t.Helper()
	m := NewSubdomainEnumeration("http://example.com:8080/app")
	if m.Target != "example.com" {
		t.Fatalf("expected port/path stripped from target, got %q", m.Target)
	}
	m.SetWordlist([]string{"www", "api", "dev"})
	m.SetThreads(3)
	return m
}

func nxdomain(host string) error {
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestSubdomainEnumeration_Execute_FoundPath(t *testing.T) {
	m := newTestSubdomainEnumeration(t)
	m.SetResolver(func(host string) ([]string, error) {
		if strings.HasPrefix(host, "www.") {
			return []string{"93.184.216.34"}, nil
		}
		return nil, nxdomain(host)
	})

	result, err := m.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" || !strings.Contains(result[0].Detail, "www.example.com") {
		t.Errorf("expected vulnerable www.example.com finding, got %+v", result[0])
	}
}

func TestSubdomainEnumeration_Execute_NXDOMAINAllSecure(t *testing.T) {
	m := newTestSubdomainEnumeration(t)
	m.SetResolver(func(host string) ([]string, error) {
		return nil, nxdomain(host)
	})

	result, err := m.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 || result[0].Status != "secure" {
		t.Fatalf("expected single secure summary row, got %+v", result)
	}
}

func TestSubdomainEnumeration_Execute_WildcardDNS(t *testing.T) {
	m := newTestSubdomainEnumeration(t)
	m.SetResolver(func(host string) ([]string, error) {
		// Wildcard zone: everything resolves to the same address.
		return []string{"10.0.0.1"}, nil
	})

	result, err := m.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("wildcard zone must not produce vulnerable findings: %+v", res)
		}
	}
	var wildcardRow, found bool
	for _, res := range result {
		if res.Status == "inconclusive" && strings.Contains(res.Detail, "Wildcard DNS detected") {
			wildcardRow = true
		}
		if res.Status == "secure" && strings.Contains(res.Detail, "No subdomains resolved") {
			found = true
		}
	}
	if !wildcardRow {
		t.Errorf("expected a single inconclusive wildcard-DNS row, got %+v", result)
	}
	if !found {
		t.Errorf("expected secure summary after wildcard filtering, got %+v", result)
	}
}

func TestSubdomainEnumeration_Execute_TransientFailuresInconclusive(t *testing.T) {
	m := newTestSubdomainEnumeration(t)
	m.SetWordlist([]string{"www", "api"}) // keep retry backoff short overall
	m.SetResolver(func(host string) ([]string, error) {
		return nil, errors.New("dial udp: connection refused")
	})

	result, err := m.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("expected single inconclusive DNS-failure row, got %+v", result)
	}
	if !strings.Contains(result[0].Detail, "DNS resolution failed") {
		t.Errorf("expected DNS-failure detail, got %q", result[0].Detail)
	}
}

func TestSubdomainEnumeration_Execute_NXDOMAINNotRetried(t *testing.T) {
	m := newTestSubdomainEnumeration(t)
	m.SetWordlist([]string{"www"})
	calls := 0
	m.SetResolver(func(host string) ([]string, error) {
		calls++
		return nil, nxdomain(host)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := m.Execute(ctx); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// One control-probe call + one definitive candidate lookup (no retries).
	if calls != 2 {
		t.Errorf("expected NXDOMAIN not to be retried (2 calls), got %d", calls)
	}
}

func TestSubdomainEnumeration__Execute_CanceledContext(t *testing.T) {
	m := NewSubdomainEnumeration("http://example.com")
	m.SetResolver(func(host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = m.Execute(ctx)
}
