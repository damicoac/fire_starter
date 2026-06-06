package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestGraphQLAdvanced_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"data":{"__typename":"Query"}}]`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Log("Expected results, got none")
	}
}

func TestGraphQLAdvanced_Execute_CanceledContext(t *testing.T) {
	module := NewGraphQLAdvanced("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestGraphQLAdvanced_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "batching not supported"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}
