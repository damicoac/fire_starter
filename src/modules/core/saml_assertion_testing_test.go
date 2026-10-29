package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSAMLAssertionTesting_Execute(t *testing.T) {
	// Baseline (malformed garbage) is rejected with 400; forged SAML payloads
	// are accepted with 200 and a positive auth signal.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "invalid_baseline_data") {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid SAML response"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Welcome! You are logged in.</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundVulnerable := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			foundVulnerable = true
		}
	}
	if !foundVulnerable {
		t.Fatalf("expected a vulnerable result when forged SAML is accepted, got %#v", result)
	}
}

func TestSAMLAssertionTesting_Execute_InconclusiveWhenBaselineFails(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil // transport failure for everything
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result when baseline request fails, got %#v", result)
	}
}

func TestSAMLAssertionTesting_Execute_NoFindingWhenSPRejects(t *testing.T) {
	// Baseline and payloads all rejected with 400 and an error page.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "Invalid SAML response"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("rejecting SP must not be flagged vulnerable, got %#v", r)
		}
	}
}

func TestSAMLAssertionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewSAMLAssertionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestSAMLAssertionTesting__Execute_InvalidURL(t *testing.T) {
	module := NewSAMLAssertionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestSAMLAssertionTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
