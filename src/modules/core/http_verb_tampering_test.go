package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHttpVerbTampering_Execute(t *testing.T) {
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

	module := NewHttpVerbTampering("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got %d", len(result))
	}
	if result[0].Status != "secure" {
		t.Fatalf("Expected secure summary for uniformly-handled verbs, got: %+v", result[0])
	}
}

func TestHttpVerbTampering_Execute_Options200NotFlagged(t *testing.T) {
	// GET baseline 401; OPTIONS/PUT return 200 (normal CORS preflight and
	// unauthenticated PUT mutation must not produce a vulnerability without
	// opt-in); every other verb honors authentication.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "OPTIONS", "PUT":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"ok": true}`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got: %+v", result)
	}
	if result[0].Status != "secure" || result[0].Detail != "All tested verbs were rejected or handled consistently with the GET baseline." {
		t.Fatalf("Unexpected result: %+v", result[0])
	}
	for _, r := range result {
		if strings.Contains(r.Detail, "OPTIONS") {
			t.Fatalf("OPTIONS must not be flagged: %+v", r)
		}
	}
}

func TestHttpVerbTampering_Execute_MutationOptIn_ConfirmedPut(t *testing.T) {
	// With explicit opt-in, a PUT that echoes the probe marker is confirmed.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "PUT" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"tamper_test":"123"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"resource": "original"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	module.SetAllowMutating(true)

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "PUT") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected a confirmed vulnerable PUT finding, got: %+v", result)
	}
}

func TestHttpVerbTampering_Execute_AuthBypassViaTrace(t *testing.T) {
	// GET requires auth but TRACE answers 200 with divergent content in both
	// status and length: the classic verb-tampering auth bypass.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "TRACE":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html>internal admin panel</html>`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "TRACE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected vulnerable TRACE auth-bypass finding, got: %+v", result)
	}
}

func TestHttpVerbTampering_Execute_BaselineFailure(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive row on baseline failure, got: %+v", result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive on baseline failure, got: %+v", result[0])
	}
}

func TestHttpVerbTampering__Execute_CanceledContext(t *testing.T) {
	module := NewHttpVerbTampering("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestHttpVerbTampering__Execute_InvalidURL(t *testing.T) {
	module := NewHttpVerbTampering("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestHttpVerbTampering__Execute_HTTPError(t *testing.T) {
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

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// Uniform 500 responses: baselines succeed, nothing diverges, no verdicts.
	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got: %+v", result)
	}
	if result[0].Status != "secure" {
		t.Fatalf("Expected secure summary on uniform 500s, got: %+v", result[0])
	}
}
