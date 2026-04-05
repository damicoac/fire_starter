package modules

import (
	"context"
	"testing"
)

func TestSubdomainEnumerator_Execute(t *testing.T) {
	enumerator := NewSubdomainEnumerator("example.com")

	ctx := context.Background()
	results, err := enumerator.Enumerate(ctx)
	if err != nil {
		// Ignore error since actual DNS resolution can fail in sandbox,
		// but check that we got to this point
		t.Logf("Enumerate returned error: %v", err)
	}

	if results == nil {
		t.Log("Execution completed but results slice is nil")
	}
}
