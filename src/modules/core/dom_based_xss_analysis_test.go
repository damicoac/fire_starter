package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestDOMBasedXSSAnalysis_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><script>eval(location.hash)</script></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewDOMBasedXSSAnalysis("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result))
	}
	if result[0].Status != "vulnerable" {
		t.Errorf("Expected status vulnerable, got %s", result[0].Status)
	}
	if result[0].Sink != "eval" {
		t.Errorf("Expected sink eval, got %s", result[0].Sink)
	}
	if result[0].Source != "location.hash" {
		t.Errorf("Expected source location.hash, got %s", result[0].Source)
	}
}

func TestDOMBasedXSSAnalysis__Execute_Benign(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><script>console.log("hello");</script></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewDOMBasedXSSAnalysis("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 findings for benign script, got %d", len(result))
	}
}

func TestDOMBasedXSSAnalysis__Execute_ScriptFetchFailure(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Path == "/app.js" {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString("")),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><script src="/app.js"></script></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewDOMBasedXSSAnalysis("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	inconclusive := false
	for _, res := range result {
		if res.Status == "inconclusive" {
			inconclusive = true
		}
	}
	if !inconclusive {
		t.Error("Expected an inconclusive row for the failed script fetch")
	}
}

func TestDOMBasedXSSAnalysis__Execute_CanceledContext(t *testing.T) {
	module := NewDOMBasedXSSAnalysis("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestDOMBasedXSSAnalysis__Execute_InvalidURL(t *testing.T) {
	module := NewDOMBasedXSSAnalysis("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestDOMBasedXSSAnalysis__Execute_HTTPError(t *testing.T) {
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

	module := NewDOMBasedXSSAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 findings for error page without scripts, got %d", len(result))
	}
}
