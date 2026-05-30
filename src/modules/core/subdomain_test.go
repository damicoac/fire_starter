package core

import (
	"context"
	"testing"
)

func TestNewSubdomainEnumerator(t *testing.T) {
	target := "example.com"
	enumerator := NewSubdomainEnumerator(target)

	if enumerator.Target != target {
		t.Errorf("Expected target domain %s, got %s", target, enumerator.Target)
	}

	if len(enumerator.Wordlist) == 0 {
		t.Error("Expected default wordlist to be populated, got empty")
	}
}

func TestSetWordlist(t *testing.T) {
	enumerator := NewSubdomainEnumerator("example.com")
	wordlist := []string{"test1", "test2"}
	enumerator.SetWordlist(wordlist)

	if len(enumerator.Wordlist) != len(wordlist) {
		t.Errorf("Expected wordlist length %d, got %d", len(wordlist), len(enumerator.Wordlist))
	}
}

func TestSetThreadsSubdomain(t *testing.T) {
	enumerator := NewSubdomainEnumerator("example.com")
	enumerator.SetThreads(20)

	if enumerator.maxThreads != 20 {
		t.Errorf("Expected 20 threads, got %d", enumerator.maxThreads)
	}

	// Test boundary
	enumerator.SetThreads(0)
	if enumerator.maxThreads != 1 {
		t.Errorf("Expected threads to default to 1 when set to <1, got %d", enumerator.maxThreads)
	}
}

func TestSubdomainEnumerator_Enumerate(t *testing.T) {
	enumerator := NewSubdomainEnumerator("example.com")

	ctx := context.Background()
	results, err := enumerator.Enumerate(ctx)
	if err != nil {
		t.Logf("Enumerate returned error: %v", err)
	}

	if results == nil {
		t.Log("Execution completed but results slice is nil")
	}
}

func TestSubdomainEnumerator_Execute_CanceledContext(t *testing.T) {
	enumerator := NewSubdomainEnumerator("example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = enumerator.Enumerate(ctx)
}

func TestSubdomainEnumerator_Execute_InvalidURL(t *testing.T) {
	enumerator := NewSubdomainEnumerator("invalid-url-:foo")
	ctx := context.Background()
	_, _ = enumerator.Enumerate(ctx)
}
