package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPathTraversalAttack_ContentMatch(t *testing.T) {
	// Test basic content matching (/etc/passwd)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome!"))
			return
		}

		// Baseline probing usually sends some random string like "nonexistent_..."
		if len(file) > 10 && file[:11] == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("File not found"))
			return
		}

		if file == "../../../etc/passwd" || file == "....//....//....//etc/passwd" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("File not found"))
	}))
	defer server.Close()

	targetURL := server.URL + "/?file=report.pdf"
	attack := NewPathTraversalAttack(targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := attack.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, res := range results {
		if res.Status == "vulnerable" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected path traversal vulnerability to be found via content match")
	}
}

// TestPathTraversalAttack_NoBaselineSkipsJudging pins the missing-baseline
// guard: when every baseline probe fails on transport errors, no vector may
// be judged against the zero-value baseline (which disables the soft-404
// gate) — the run yields a single inconclusive row instead.
func TestPathTraversalAttack_NoBaselineSkipsJudging(t *testing.T) {
	module := NewPathTraversalAttack("http://example.com")
	module.Client = &http.Client{Transport: &customTransport{roundTrip: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused by mock")
	}}}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected exactly 1 inconclusive row when all baselines fail, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status when all baselines fail, got %q (%s)", result[0].Status, result[0].Detail)
	}
	if result[0].Status == "vulnerable" {
		t.Fatalf("no vector may be judged without a baseline: %+v", result[0])
	}
}

func TestPathTraversalAttack_Execute_CanceledContext(t *testing.T) {
	module := NewPathTraversalAttack("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestPathTraversalAttack_Execute_InvalidURL(t *testing.T) {
	module := NewPathTraversalAttack("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestPathTraversalAttack_Execute_HTTPError(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "internal server error"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPathTraversalAttack("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
