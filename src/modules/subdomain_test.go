package modules

import (
	"context"
	"testing"
	"time"
)

func TestNewSubdomainEnumerator(t *testing.T) {
	enum := NewSubdomainEnumerator("example.com")
	
	if enum.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", enum.Target)
	}
	
	if len(enum.Wordlist) == 0 {
		t.Error("Expected default wordlist to be populated")
	}
	
	if enum.maxThreads != 50 {
		t.Errorf("Expected default threads 50, got %d", enum.maxThreads)
	}
}

func TestSetWordlist(t *testing.T) {
	enum := NewSubdomainEnumerator("example.com")
	
	customList := []string{"foo", "bar"}
	enum.SetWordlist(customList)
	
	if len(enum.Wordlist) != 2 {
		t.Errorf("Expected 2 words in wordlist, got %d", len(enum.Wordlist))
	}
}

func TestSetSubdomainThreads(t *testing.T) {
	enum := NewSubdomainEnumerator("example.com")
	
	enum.SetThreads(25)
	if enum.maxThreads != 25 {
		t.Errorf("Expected threads 25, got %d", enum.maxThreads)
	}
	
	enum.SetThreads(0)
	if enum.maxThreads != 1 {
		t.Errorf("Expected threads to default to 1 for invalid value, got %d", enum.maxThreads)
	}
}

func TestEnumerateWithPorts(t *testing.T) {
	// This is a real DNS enumeration - skip if running in fast mode
	if testing.Short() {
		t.Skip("skipping real DNS enumeration")
	}
	
	enum := NewSubdomainEnumerator("google.com")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	results, err := enum.EnumerateWithPorts(ctx)
	if err != nil {
		t.Fatalf("EnumerateWithPorts failed: %v", err)
	}
	
	// Just verify it returns without error; actual subdomain count varies by target
	_ = results
}
