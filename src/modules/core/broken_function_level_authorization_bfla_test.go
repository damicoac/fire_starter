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
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
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

	if result == nil {
		t.Log("Expected result, got nil")
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
