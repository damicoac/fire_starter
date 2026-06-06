package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestBusinessLogicBypass_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success", "order": "123"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Log("Expected results, got none")
	}
}

func TestBusinessLogicBypass_Execute_CanceledContext(t *testing.T) {
	module := NewBusinessLogicBypass("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestBusinessLogicBypass_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "no active cart"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}
