package modules

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestJsonHijackingTest_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`["item1", "item2"]`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJsonHijackingTest("http://example.com")

	// Override the client to use the mock transport
	module.client.Transport = mockTransport

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil || len(result) == 0 {
		t.Fatal("Expected result indicating vulnerability, got none")
	}

	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got: %s", result[0].Status)
	}
}
