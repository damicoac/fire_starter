// File overview:
// Test coverage for this module. These tests exist to lock expected behavior and prevent regressions in stage routing, payload handling, and integration boundaries.

package openai

import (
	"encoding/json"
	"testing"
)

func logMockData(t *testing.T, label string, value any) {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Logf("mock data %s: %#v (marshal error: %v)", label, value, err)
		return
	}

	t.Logf("mock data %s: %s", label, string(encoded))
}
