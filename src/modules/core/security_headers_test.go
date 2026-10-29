package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityHeaders_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "text/html")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected missing-header findings, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected vulnerable finding, got: %+v", r)
		}
	}
}

func TestSecurityHeaders_Execute_CanceledContext(t *testing.T) {
	module := NewSecurityHeaders("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestSecurityHeaders_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Security-Policy", "default-src 'self'")
			h.Set("Strict-Transport-Security", "max-age=31536000")
			h.Set("X-Frame-Options", "DENY")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected exactly one secure summary, got %d results", len(res))
	}
	if res[0].Status != "secure" || res[0].Detail != "All checked security headers present" {
		t.Fatalf("Unexpected summary: %+v", res[0])
	}
}

func TestSecurityHeaders_Execute_Twice_IdenticalResults(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "text/html")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html>hello</html>`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()

	first, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("First Execute failed: %v", err)
	}
	second, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Second Execute failed: %v", err)
	}

	if len(first) == 0 {
		t.Fatalf("Expected findings on first run, got none")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Repeat scan dropped results (per-run dedup broken): first=%+v second=%+v", first, second)
	}
}

// After a finding-bearing run against a non-compliant server, a repeat run
// against a compliant server must still emit its secure summary row.
func TestSecurityHeaders_Execute_CompliantAfterFindings(t *testing.T) {
	missing := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "text/html")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html>hello</html>`)),
				Header:     h,
			}
		},
	}
	cleanupMissing := SetMockTransport(missing)
	defer cleanupMissing()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()

	first, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("First Execute failed: %v", err)
	}
	if len(first) == 0 {
		t.Fatalf("Expected findings on first run, got none")
	}

	// The module client captured the transport at construction, so rebind it
	// directly for the second run against the compliant server.
	compliant := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Security-Policy", "default-src 'self'")
			h.Set("Strict-Transport-Security", "max-age=31536000")
			h.Set("X-Frame-Options", "DENY")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	module.Client.Transport = compliant

	second, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Second Execute failed: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("Expected exactly one secure summary on compliant second run, got %d results: %+v", len(second), second)
	}
	if second[0].Status != "secure" || second[0].Detail != "All checked security headers present" {
		t.Fatalf("Unexpected summary on second run: %+v", second[0])
	}
}

func TestSecurityHeaders_Execute_404(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`Not Found`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com/dump.sql")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected one summary for non-2xx endpoint, got %d", len(res))
	}
	if res[0].Status != "inconclusive" || !strings.Contains(res[0].Detail, "404") {
		t.Fatalf("Expected inconclusive non-2xx summary, got: %+v", res[0])
	}
}

func TestSecurityHeaders_Execute_ProbeError(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected one inconclusive summary for probe failure, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status, got: %+v", res[0])
	}
}

func TestSecurityHeaders_Execute_JSON(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com/api/v1")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) == 0 {
		t.Fatalf("Expected CSP/HSTS missing, got no results")
	}
	for _, r := range res {
		if strings.Contains(r.Detail, "X-Frame-Options") {
			t.Fatalf("Did not expect X-Frame-Options missing for JSON API, but got: %s", r.Detail)
		}
	}
}
