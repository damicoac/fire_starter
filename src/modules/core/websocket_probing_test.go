package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestWebSocketProbing_Execute(t *testing.T) {
	// Spoofed-Origin handshake upgrades, but the no-Origin control request is
	// rejected: positive CSWSH evidence.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Header.Get("Origin") == "http://evil.com" {
				return &http.Response{
					StatusCode: http.StatusSwitchingProtocols,
					Body:       io.NopCloser(bytes.NewBufferString("")),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewWebSocketProbing("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected vulnerable CSWSH findings, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected vulnerable finding, got: %+v", r)
		}
	}
}

func TestWebSocketProbing_Execute_AcceptsAnyOrigin_Inconclusive(t *testing.T) {
	// Public anonymous endpoint: 101 for any Origin (and for the no-Origin
	// control) — unauthenticated, so CSWSH impact cannot be confirmed.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewWebSocketProbing("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected inconclusive rows for any-origin endpoint, got none")
	}
	for _, r := range result {
		if r.Status != "inconclusive" {
			t.Fatalf("Expected inconclusive (unauthenticated 101), got: %+v", r)
		}
	}
}

func TestWebSocketProbing_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid origin"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewWebSocketProbing("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected exactly one secure summary, got %d results", len(res))
	}
	if res[0].Status != "secure" {
		t.Fatalf("Expected secure summary, got: %+v", res[0])
	}
}

func TestWebSocketProbing_Execute_AllProbesFailed(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewWebSocketProbing("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected exactly one inconclusive summary on probe failure, got %d results", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive on probe failure, got: %+v", res[0])
	}
}

func TestWebSocketProbing_Execute_CanceledContext(t *testing.T) {
	module := NewWebSocketProbing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}
