package core

import (
	"bytes"
	"context"
	"fmt"
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
	module.Client.Transport = mockTransport

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected result indicating vulnerability, got none")
	}

	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got: %s", result[0].Status)
	}
}

func TestJsonHijackingTest__Execute_CanceledContext(t *testing.T) {
	module := NewJsonHijackingTest("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestJsonHijackingTest__Execute_InvalidURL(t *testing.T) {
	module := NewJsonHijackingTest("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestJsonHijackingTest__Execute_HTTPError(t *testing.T) {
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

	module := NewJsonHijackingTest("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func init() {
	RegisterModule("json_hijacking_test", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting JsonHijackingTest on: %s", target))

		tester := NewJsonHijackingTest(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
