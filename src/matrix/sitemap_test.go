package matrix_test

import (
	"testing"

	"fire_starter/src/matrix"
)

func TestSiteMap_AddURLAndCount(t *testing.T) {
	sm := matrix.NewSiteMap("example.com")

	err := sm.AddURL("http://example.com/api/v1/users", "GET", 200, "application/json", []string{"page", "limit"})
	if err != nil {
		t.Fatalf("unexpected error adding URL: %v", err)
	}

	err = sm.AddURL("http://example.com/api/v1/auth/login", "POST", 200, "application/json", []string{"username", "password"})
	if err != nil {
		t.Fatalf("unexpected error adding URL: %v", err)
	}

	// Root "/" + "api" + "v1" + "users" + "auth" + "login" = 6 nodes
	if count := sm.NodeCount(); count != 6 {
		t.Errorf("expected 6 nodes in site map, got %d", count)
	}
}
