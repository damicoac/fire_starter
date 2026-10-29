package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func corsReflectingOriginMock() *MockTransport {
	return &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
			h.Set("Access-Control-Allow-Credentials", "true")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
}

func TestCorsMisconfigurationAnalysis_Execute_ReflectedOriginWithCredentials(t *testing.T) {
	cleanup := SetMockTransport(corsReflectingOriginMock())
	defer cleanup()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected vulnerable CORS findings, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected vulnerable finding, got: %+v", r)
		}
	}
}

func TestCorsMisconfigurationAnalysis_Execute_WildcardOriginOnly(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Access-Control-Allow-Origin", "*")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected a summary row, got none")
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("Wildcard origin without credentials must not be flagged vulnerable: %+v", r)
		}
	}
	if result[len(result)-1].Status != "secure" {
		t.Fatalf("Expected secure summary for wildcard-only server, got: %+v", result)
	}
}

func TestCorsMisconfigurationAnalysis_Execute_WildcardWithCredentials(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Credentials", "true")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one deduplicated inconclusive row for ACAO * + credentials, got %d results: %+v", len(result), result)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("Wildcard origin with credentials is not exploitable for credentialed reads: %+v", r)
		}
		if r.Status != "inconclusive" {
			t.Fatalf("Expected an inconclusive informational row for ACAO * + credentials, got: %+v", r)
		}
	}
}

// A transport failure on the confirming cross-origin GET must never allow the
// "all origins rejected" secure summary.
func TestCorsMisconfigurationAnalysis_Execute_GetConfirmationFailed(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet {
				return nil, context.DeadlineExceeded
			}
			h := make(http.Header)
			h.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
			h.Set("Access-Control-Allow-Credentials", "true")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}, nil
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive row when GET confirmation fails, got %d results: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive when GET confirmation fails, got: %+v", result[0])
	}
}

func TestCorsMisconfigurationAnalysis_Execute_PreflightOnlyReflection(t *testing.T) {
	// Server reflects on the preflight only; the GET the browser issues is
	// not allowed, so nothing is exploitable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			if req.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
				h.Set("Access-Control-Allow-Credentials", "true")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("Preflight-only reflection must not be flagged vulnerable: %+v", r)
		}
	}
}

func TestCorsMisconfigurationAnalysis_Execute_AllProbesFailed(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive summary, got %d results", len(result))
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive on all-probes-failed, got: %+v", result[0])
	}
}

func TestCorsMisconfigurationAnalysis__Execute_CanceledContext(t *testing.T) {
	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestCorsMisconfigurationAnalysis__Execute_InvalidURL(t *testing.T) {
	module := NewCorsMisconfigurationAnalysis("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestCorsMisconfigurationAnalysis__Execute_HTTPError(t *testing.T) {
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

	module := NewCorsMisconfigurationAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// 500 responses complete the probes but reject every malicious origin:
	// exactly one secure summary row, never a fabricated "safe"/vulnerable.
	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got %d", len(result))
	}
	if result[0].Status != "secure" {
		t.Fatalf("Expected secure summary, got: %+v", result[0])
	}
}
