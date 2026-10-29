package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestBusinessLogicBypass_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "POST" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success", "order": "123"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Body:       io.NopCloser(bytes.NewBufferString(`{"detail": "method not allowed"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected results, got none")
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got %q", result[0].Status)
	}
}

func TestBusinessLogicBypass_Execute_CanceledContext(t *testing.T) {
	module := NewBusinessLogicBypass("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestBusinessLogicBypass_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "no active cart"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	// All endpoints explicitly denied: a single summary row, no findings.
	if len(res) != 1 {
		t.Fatalf("Expected exactly 1 summary result, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive summary status, got %q", res[0].Status)
	}
}

func TestBusinessLogicBypass_NegativePhrasingIgnored(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "Operation not successful", "error": "Order was not confirmed"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	// Negative phrasing on 2xx counts as an explicit denial; expect only the
	// summary row, no vulnerable finding.
	if len(res) != 1 {
		t.Fatalf("Expected exactly 1 summary result, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive summary status, got %q", res[0].Status)
	}
}

func TestBusinessLogicBypass_UniformSuccessBodyNotConfirmed(t *testing.T) {
	// Marketing-style success text on every request (same body for GET and
	// POST) must not be confirmed as a bypass: the differential cannot
	// distinguish the direct hit from the control response.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Read our customer Success Stories and see confirmed case studies!</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBusinessLogicBypass("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Errorf("Expected static success-text page to not be flagged, got: %s", r.Detail)
		}
	}
}
