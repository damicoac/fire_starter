package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBrokenFunctionLevelAuthorizationBfla_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Path == "/nonexistent_admin_path_12345" {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`404 not found`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"admin_panel": "users", "config": "secret_key_12345_long_content_exceeding_500_bytes_threshold_abcdefghijklmnopqrstuvwxyz0123456789"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBrokenFunctionLevelAuthorizationBfla("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected finding for exposed admin endpoint, got 0")
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got %q", result[0].Status)
	}
}

func TestBrokenFunctionLevelAuthorizationBfla_LoginRedirectIgnored(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Please login with your username and password to authenticate.</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBrokenFunctionLevelAuthorizationBfla("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Expected login redirect to be ignored, got vulnerable finding: %s", r.Detail)
		}
	}
}

func TestBrokenFunctionLevelAuthorizationBfla_GenericPathRequiresAdminMarkers(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Path == "/nonexistent_admin_path_12345" {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`404 not found`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Welcome to our marketing page with lots of content to exceed the length threshold aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBrokenFunctionLevelAuthorizationBfla("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, r := range result {
		if r.Status == "vulnerable" && (strings.HasSuffix(r.Detail, "/config") || strings.HasSuffix(r.Detail, "/manage")) {
			t.Errorf("Expected non-admin content on generic paths to be ignored, got vulnerable finding: %s", r.Detail)
		}
	}
}

func TestBrokenFunctionLevelAuthorizationBfla__Execute_CanceledContext(t *testing.T) {
	module := NewBrokenFunctionLevelAuthorizationBfla("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestBrokenFunctionLevelAuthorizationBfla__Execute_InvalidURL(t *testing.T) {
	module := NewBrokenFunctionLevelAuthorizationBfla("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestBrokenFunctionLevelAuthorizationBfla__Execute_HTTPError(t *testing.T) {
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

	module := NewBrokenFunctionLevelAuthorizationBfla("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// With no 200 responses at all the module must not stay silent: it emits
	// exactly one inconclusive summary row instead of findings.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive summary row on uniform 500s, got %d results: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status, got %q", result[0].Status)
	}
}
