package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The new success oracle: the probe payload must yield a strict positive JSON
// signal (2xx, success/authenticated true or non-empty string token) AND the
// same endpoint with a deliberately invalid code must produce a
// failure-indicating difference.
func TestMFABypass_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "__firestarter_invalid_code__") {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid code"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"success": true, "token": "xyz"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMFABypass("http://example.com")
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

// An endpoint that answers identically to every POST (echo/error pages) can
// show a positive-shaped body but provides no differential: no bypass may be
// claimed.
func TestMFABypass_Execute_EchoServerNoDifferential(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"success": true, "token": "xyz"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMFABypass("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected single inconclusive summary result on echo server, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status on echo server, got: %s", result[0].Status)
	}
}

// Failure-shaped token values ("token":"expired", "token":"invalid") must not
// satisfy the "token" positive marker.
func TestMFABypass_Execute_NoFindingOnFailureShapedToken(t *testing.T) {
	for _, body := range []string{
		`{"token":"expired"}`,
		`{"token":"invalid"}`,
		`{"success":false,"token":"error: code rejected"}`,
	} {
		tokenBody := body
		mockTransport := &MockTransport{
			RoundTripFunc: func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(tokenBody)),
					Header:     make(http.Header),
				}
			},
		}
		cleanup := SetMockTransport(mockTransport)

		module := NewMFABypass("http://example.com")
		result, err := module.Execute(context.Background())
		cleanup()
		if err != nil {
			t.Fatalf("Execute failed for body %s: %v", tokenBody, err)
		}
		for _, r := range result {
			if r.Status == "vulnerable" {
				t.Fatalf("failure-shaped token body %s must not be judged vulnerable", tokenBody)
			}
		}
	}
}

func TestMFABypass_Execute_CanceledContext(t *testing.T) {
	module := NewMFABypass("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestMFABypass_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid code"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMFABypass("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected single inconclusive summary result, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status on rejected codes, got: %s", res[0].Status)
	}
}
