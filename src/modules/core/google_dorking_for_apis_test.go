package core

import (
	"strings"
	"testing"
)

func TestNewGoogleDorkingForAPIs(t *testing.T) {
	d := NewGoogleDorkingForAPIs("https://api.example.com/v1/users")
	if d.Target != "api.example.com" {
		t.Fatalf("expected normalized target api.example.com, got %s", d.Target)
	}
}

func TestGoogleDorkingForAPIsGenerate(t *testing.T) {
	d := NewGoogleDorkingForAPIs("example.com")
	results := d.Generate()

	if len(results) != 8 {
		t.Fatalf("expected 8 generated dorks, got %d", len(results))
	}
	for _, r := range results {
		if strings.Contains(r.Query, "site:*.") {
			t.Errorf("wildcard site: operator is unsupported by Google: %s", r.Query)
		}
		if !strings.HasPrefix(r.Query, "site:example.com") {
			t.Errorf("expected site: prefix with concrete domain, got %s", r.Query)
		}
	}
}

func TestGoogleDorkingForAPIs_StripsPort(t *testing.T) {
	d := NewGoogleDorkingForAPIs("http://example.com:8080/api")
	if d.Target != "example.com" {
		t.Fatalf("expected port stripped from target, got %s", d.Target)
	}
	results := d.Generate()
	for _, r := range results {
		if strings.Contains(r.Query, ":8080") {
			t.Errorf("port leaked into query: %s", r.Query)
		}
	}
}

func TestGoogleDorkingForAPIsGenerateFields(t *testing.T) {
	d := NewGoogleDorkingForAPIs("example.com")
	results := d.Generate()

	for _, r := range results {
		if r.Query == "" {
			t.Fatal("expected non-empty query")
		}
		if r.SearchURL == "" {
			t.Fatal("expected non-empty search url")
		}
		if r.Category == "" {
			t.Fatal("expected non-empty category")
		}
	}
}

func TestGoogleDorkingForAPIsGenerateEmptyTarget(t *testing.T) {
	d := NewGoogleDorkingForAPIs("   ")
	if d.Target != "" {
		t.Fatalf("expected empty target, got %s", d.Target)
	}

	results := d.Generate()
	if len(results) != 0 {
		t.Fatalf("expected no generated results for empty target, got %d", len(results))
	}
}

func TestGoogleDorkingForAPIs_Execute_CanceledContext(t *testing.T) {
	d := NewGoogleDorkingForAPIs("https://api.example.com/v1")
	_ = d.Generate()
}

func TestGoogleDorkingForAPIs_Execute_InvalidURL(t *testing.T) {
	d := NewGoogleDorkingForAPIs("http://invalid-url-:foo")
	_ = d.Generate()
}

func TestGoogleDorkingForAPIs_Execute_HTTPError(t *testing.T) {
	d := NewGoogleDorkingForAPIs("https://api.example.com/v1")
	_ = d.Generate()
}
