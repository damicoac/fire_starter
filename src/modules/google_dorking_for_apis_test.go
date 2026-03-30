package modules

import "testing"

func TestNewGoogleDorkingForAPIs(t *testing.T) {
	d := NewGoogleDorkingForAPIs("https://api.example.com/v1/users")
	if d.Target != "api.example.com" {
		t.Fatalf("expected normalized target api.example.com, got %s", d.Target)
	}
}

func TestGoogleDorkingForAPIsGenerate(t *testing.T) {
	d := NewGoogleDorkingForAPIs("example.com")
	results := d.Generate()

	if len(results) != 16 {
		t.Fatalf("expected 16 generated dorks, got %d", len(results))
	}

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
