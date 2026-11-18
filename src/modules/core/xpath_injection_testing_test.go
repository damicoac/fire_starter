package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestXpathInjectionTesting_Execute(t *testing.T) {
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

	module := NewXpathInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 results for a clean JSON endpoint, got %d: %+v", len(result), result)
	}
}

// A marker already present in the payload-free baseline body is not injection
// evidence: no vulnerable row may be emitted even though every probe response
// carries the error signature.
func TestXpathInjectionTesting_Execute_BaselineSuppressedMarker(t *testing.T) {
	errorPage := `<html><body>Warning: XPath query syntax error in invalid expression</body></html>`
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(errorPage)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXpathInjectionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Marker present in baseline must suppress the finding: %+v", r)
		}
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 results when the baseline carries the error marker, got %+v", result)
	}
}

// The error marker counts only when the payload-free baseline body does not
// carry it: every probe that surfaces a fresh marker is a vulnerable row.
func TestXpathInjectionTesting_Execute_MarkerOnlyOnProbes(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.RawQuery == "" {
				// Payload-free baseline: clean page.
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Search results</body></html>`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`Exception: xpath syntax error in expression`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXpathInjectionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != len(xpathPayloads) {
		t.Fatalf("Expected one vulnerable row per payload (%d), got %d: %+v", len(xpathPayloads), len(result), result)
	}
	for _, r := range result {
		if r.Status != "vulnerable" || !strings.Contains(r.Detail, "XPath Injection detected") {
			t.Errorf("Expected vulnerable row with detection detail, got %+v", r)
		}
	}
}

// When every probe fails at the transport level (while the baseline
// succeeded), the module must emit one inconclusive summary row instead of
// looking clean.
func TestXpathInjectionTesting_Execute_AllProbesFailed(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.RawQuery == "" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html><body>ok</body></html>`)),
					Header:     make(http.Header),
				}
			}
			return nil // transport error for every payload probe
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXpathInjectionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("Expected exactly one inconclusive row for an all-failed probe run, got %+v", result)
	}
	if !strings.Contains(result[0].Detail, "could not be assessed") {
		t.Errorf("Expected all-failed detail wording, got %q", result[0].Detail)
	}
}

// A failing baseline request cannot support a differential judgment: the
// module must emit one inconclusive row and skip probing entirely.
func TestXpathInjectionTesting_Execute_BaselineFailed(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil // transport error, including the baseline request
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXpathInjectionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("Expected exactly one inconclusive row when the baseline fails, got %+v", result)
	}
	if !strings.Contains(result[0].Detail, "Baseline request failed") {
		t.Errorf("Expected baseline-failure detail wording, got %q", result[0].Detail)
	}
}

func TestXpathInjectionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewXpathInjectionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The canceled context fails the baseline request, so the module reports
	// one inconclusive row and probes nothing.
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("Expected one inconclusive row for a canceled context, got %+v", result)
	}
}

func TestXpathInjectionTesting__Execute_InvalidURL(t *testing.T) {
	// EnsureHTTPPrefix rewrites the malformed input into a parseable (but
	// garbage) URL, so Execute cannot fail on parsing; the contract is that a
	// garbage target produces no findings.
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

	module := NewXpathInjectionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Garbage target must not produce findings: %+v", r)
		}
	}
}

func TestXpathInjectionTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewXpathInjectionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Generic 500 error page must not be flagged vulnerable: %+v", r)
		}
	}
	if len(result) != 0 {
		t.Errorf("Expected no findings for a generic 500 page, got %+v", result)
	}
}
