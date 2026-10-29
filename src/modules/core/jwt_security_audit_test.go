package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestJWTSecurityAudit_Execute_DifferentialAlgNoneAttribution(t *testing.T) {
	callCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			callCount++
			headers := make(http.Header)
			if callCount == 1 {
				headers.Add("WWW-Authenticate", "Bearer")
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     headers,
				}
			}

			auth := req.Header.Get("Authorization")
			if strings.Contains(auth, "eyJhbGciOiJub25l") || strings.Contains(auth, "eyJhbGciOiJOb25l") || strings.Contains(auth, "eyJhbGciOiJOT05FI") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok","scope":"admin","firestarter_claim":"allow"}`)),
					Header:     make(http.Header),
				}
			}

			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 || result[0].Status != "vulnerable" {
		t.Fatalf("expected vulnerable result with alg=none-specific acceptance, got %#v", result)
	}
}

func TestJWTSecurityAudit_Execute_InconclusiveWithoutJWTArtifacts(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result without JWT artifacts, got %#v", result)
	}
}

func TestJWTSecurityAudit_Execute_InconclusiveWhenGenericBearerBypass(t *testing.T) {
	callCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			callCount++
			headers := make(http.Header)
			if callCount == 1 {
				headers.Add("WWW-Authenticate", "Bearer")
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     headers,
				}
			}
			if req.Header.Get("Authorization") != "" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result for generic bearer bypass, got %#v", result)
	}
}

func TestJWTSecurityAudit_Execute_InconclusiveWhenJWTNoneRejected(t *testing.T) {
	callCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			callCount++
			headers := make(http.Header)
			if callCount == 1 {
				headers.Add("WWW-Authenticate", "Bearer")
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     headers,
				}
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// Weak negative evidence cannot confirm security; the framework maps it
	// to inconclusive (only confirmed negative evidence yields "secure").
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result when forged JWTs are rejected, got %#v", result)
	}
}

func TestJWTSecurityAudit_Execute_InconclusiveWhenBaselineNotAuthGated(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			headers := make(http.Header)
			headers.Add("WWW-Authenticate", "Bearer")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"public"}`)),
				Header:     headers,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result when baseline is not auth-gated, got %#v", result)
	}
}

func TestJWTSecurityAudit_Execute_InconclusiveNamingFailedProbes(t *testing.T) {
	callCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			callCount++
			headers := make(http.Header)
			if callCount == 1 {
				// Baseline succeeds and is auth-gated; every probe afterwards
				// fails at the transport layer.
				headers.Add("WWW-Authenticate", "Bearer")
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     headers,
				}
			}
			return nil // transport failure
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJWTSecurityAudit("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive when probes fail, got %#v", result)
	}
	if !strings.Contains(result[0].Detail, "no_token") || !strings.Contains(result[0].Detail, "alg_none_1") {
		t.Fatalf("expected detail to name failed probes, got %q", result[0].Detail)
	}
}

func TestJWTSecurityAudit__Execute_CanceledContext(t *testing.T) {
	module := NewJWTSecurityAudit("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestJWTSecurityAudit__Execute_InvalidURL(t *testing.T) {
	module := NewJWTSecurityAudit("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestJWTSecurityAudit__Execute_HTTPError(t *testing.T) {
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

	module := NewJWTSecurityAudit("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result when endpoint errors on every request, got %#v", result)
	}
}
