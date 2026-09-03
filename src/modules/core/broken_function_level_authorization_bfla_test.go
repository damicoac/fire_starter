package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
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

	if len(result) > 0 {
		t.Errorf("Expected login redirect to be ignored, got %d findings", len(result))
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
	_, _ = module.Execute(ctx)
}
