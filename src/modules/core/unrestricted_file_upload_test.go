package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestUnrestrictedFileUpload_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Log("Expected results, got none")
	}
}

func TestUnrestrictedFileUpload_Execute_CanceledContext(t *testing.T) {
	module := NewUnrestrictedFileUpload("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestUnrestrictedFileUpload_Execute_HTTPError(t *testing.T) {
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

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results on 500 error, got %d", len(res))
	}
}
