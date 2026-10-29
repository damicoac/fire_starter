package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestBufferOverflowProbing_Execute(t *testing.T) {
	// Uniform 200: oversized input is accepted, expect zero findings.
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

	module := NewBufferOverflowProbing("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results on clean target, got %d: %+v", len(result), result)
	}
}

// TestBufferOverflowProbing_DifferentialVulnerable pins the differential
// judge: a 500 only on oversized input (baseline stays 200) is a vulnerable
// overflow, while a uniform 500 is not.
func TestBufferOverflowProbing_DifferentialVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			input := req.URL.Query().Get("input")
			if len(input) > 1000 {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "buffer overflow"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBufferOverflowProbing("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	vulnerable := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			vulnerable = true
		}
	}
	if !vulnerable {
		t.Fatalf("expected a vulnerable finding when only oversized input triggers 500, got %+v", result)
	}
}

func TestBufferOverflowProbing__Execute_CanceledContext(t *testing.T) {
	module := NewBufferOverflowProbing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestBufferOverflowProbing__Execute_InvalidURL(t *testing.T) {
	module := NewBufferOverflowProbing("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

// TestBufferOverflowProbing__Execute_HTTPError pins the baseline differential:
// a uniform 500 (pre-broken endpoint) yields zero vulnerable findings.
func TestBufferOverflowProbing__Execute_HTTPError(t *testing.T) {
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

	module := NewBufferOverflowProbing("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("uniform-500 target must yield 0 overflow findings (baseline also 500), got %d: %+v", len(result), result)
	}
}
