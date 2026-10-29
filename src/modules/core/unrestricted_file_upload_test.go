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
		t.Fatalf("Expected results, got none")
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got: %s", result[0].Status)
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
	if len(res) != 1 {
		t.Fatalf("Expected single inconclusive summary result, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status on 500 error, got: %s", res[0].Status)
	}
}

func TestUnrestrictedFileUpload_Execute_RejectionBodyOn200(t *testing.T) {
	// A 200 with a differently-worded rejection body must not be judged
	// vulnerable; only the inconclusive summary remains.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"success":false,"message":"file extension rejected"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	res, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("Expected no vulnerable findings on rejection body, got %#v", res)
		}
	}
}
