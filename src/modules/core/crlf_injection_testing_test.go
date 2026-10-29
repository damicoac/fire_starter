package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockCRLFResponse builds a mocked response with the given status and headers.
func mockCRLFResponse(status int, header http.Header) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
		Header:     header,
	}
}

func TestCrlfInjectionTesting_Execute(t *testing.T) {
	// Uniform 200 with no injected headers: expect zero findings.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return mockCRLFResponse(http.StatusOK, make(http.Header))
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCrlfInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results on clean target, got %d: %+v", len(result), result)
	}
}

// TestCrlfInjectionTesting_VulnerableHeader pins the header-scan judge: a
// server that echoes our Set-Cookie marker yields exactly one vulnerable
// finding, not zero.
func TestCrlfInjectionTesting_VulnerableHeader(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			// Only the exact first payload variant maps to a successful
			// header injection so the assertion can pin "exactly 1"
			// (the space and '#' variants stay clean).
			if strings.HasPrefix(req.URL.Path, "/\r\nSet-Cookie:crlf=injected") {
				header.Set("Set-Cookie", "crlf=injected")
			}
			return mockCRLFResponse(http.StatusOK, header)
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCrlfInjectionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 vulnerable result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("expected status vulnerable, got %q", result[0].Status)
	}
}

// TestCrlfInjectionTesting_WireEncoding pins the single-encoding contract: the
// literal CRLF payload must appear on the wire exactly once as %0D%0A, not be
// double-escaped into %250D%250A.
func TestCrlfInjectionTesting_WireEncoding(t *testing.T) {
	var sawEncodedCRLF atomic.Bool
	var sawDoubleEncoded atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "%0D%0ASet-Cookie") {
			sawEncodedCRLF.Store(true)
		}
		if strings.Contains(r.RequestURI, "%250D") || strings.Contains(r.RequestURI, "%250d") {
			sawDoubleEncoded.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	module := NewCrlfInjectionTesting(ts.URL)
	ctx := context.Background()
	if _, err := module.Execute(ctx); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !sawEncodedCRLF.Load() {
		t.Fatalf("expected wire request to contain single-encoded %%0D%%0ASet-Cookie")
	}
	if sawDoubleEncoded.Load() {
		t.Fatalf("wire request contained double-encoded CRLF (%%250D): payload was re-escaped")
	}
}

func TestCrlfInjectionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewCrlfInjectionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestCrlfInjectionTesting__Execute_InvalidURL(t *testing.T) {
	module := NewCrlfInjectionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestCrlfInjectionTesting__Execute_HTTPError(t *testing.T) {
	// Uniform 500 with no injected headers: expect zero vulnerable findings.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return mockCRLFResponse(http.StatusInternalServerError, make(http.Header))
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCrlfInjectionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("unexpected vulnerable finding on uniform-500 target: %+v", r)
		}
	}
}
