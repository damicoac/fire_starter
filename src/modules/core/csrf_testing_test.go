package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const csrfTestFormHTML = `<html><body><form method="post" action="/update"><input type="hidden" name="csrf_token" value="abc"><input name="user"></form></body></html>`

func TestCSRFTesting_Execute_TokenAcceptedPath(t *testing.T) {
	// The currently-FP path: a form with a token field where the endpoint
	// accepts POSTs both with and without it. Must NOT report vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"updated"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Token-accepted path must not report vulnerable: %s", res.Detail)
		}
	}
	if len(result) == 0 {
		t.Error("Expected at least one result row for the tested form")
	}
}

func TestCSRFTesting_Execute_TokenRejectedFlow(t *testing.T) {
	// Token enforced: the token-less POST is rejected while the token-bearing
	// POST is accepted. Must NOT report vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "csrf_token=abc") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status":"updated"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":"forbidden"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Token-rejected flow must not report vulnerable: %s", res.Detail)
		}
	}
}

func TestCSRFTesting_Execute_NoForms(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("No-forms target must not report vulnerable: %s", res.Detail)
		}
	}
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Errorf("Expected one inconclusive row for a formless target, got %+v", result)
	}
}

func TestCSRFTesting__Execute_CanceledContext(t *testing.T) {
	module := NewCSRFTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestCSRFTesting__Execute_InvalidURL(t *testing.T) {
	module := NewCSRFTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestCSRFTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Error-page baseline must not report vulnerable: %s", res.Detail)
		}
	}
}
