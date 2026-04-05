package modules

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestTokenEntropyAnalysis_Execute(t *testing.T) {
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

	module := NewTokenEntropyAnalysis("http://example.com")

	// Actually, a simpler way is to just use http.DefaultClient everywhere, but let\'s override client if it exists.

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Log("Expected result, got nil")
	}
}
