package core

import (
	"bytes"
	"context"
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

func TestPathTraversalAttack_StatusDiff(t *testing.T) {
	// Test status diffing (403 vs 404 baseline)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")

		// Baseline probing
		if len(file) > 10 && file[:11] == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if file == "../../../../../../../../windows/win.ini" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	targetURL := server.URL + "/?file=doc.txt"
	attack := NewPathTraversalAttack(targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := attack.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, res := range results {
		if res.Status == "vulnerable" && res.Detail != "" {
			// Detail should mention status diff
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected path traversal vulnerability to be found via status diff (403 vs 404)")
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
