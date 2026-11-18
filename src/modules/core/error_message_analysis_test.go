package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestErrorMessageAnalysis_Execute_Tomcat(t *testing.T) {
	// Baseline GET (path "/") is benign; every probe returns a canned 500
	// leaking the Tomcat version. Dedupe must collapse the 5 probes into a
	// single vulnerable result.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			// Baseline GET (host example.com, empty path) is benign; every
			// probe (different host suffix or real path) returns a canned 500.
			if req.URL.Host == "example.com" && req.URL.Path == "" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("Welcome")),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("<h1>Apache Tomcat/9.0.83</h1>")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewErrorMessageAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 vulnerable result, got %d", len(result))
	}
	if result[0].Status != "vulnerable" {
		t.Errorf("Expected status vulnerable, got %s", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "Tomcat Error") {
		t.Errorf("Expected Tomcat Error detail, got %s", result[0].Detail)
	}
}

func TestErrorMessageAnalysis_Execute_Benign(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("Welcome")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewErrorMessageAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 results for benign target, got %d", len(result))
	}
}

func TestErrorMessageAnalysis_Execute_WelcomePageSignature(t *testing.T) {
	// A Tomcat welcome page (HTTP 200) leaking the version on every request
	// must not be reported: the signature is present in the baseline body.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("<h1>Apache Tomcat/9.0.83</h1>")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewErrorMessageAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 results when the signature is already in the baseline, got %d", len(result))
	}
}

func TestErrorMessageAnalysis__Execute_CanceledContext(t *testing.T) {
	module := NewErrorMessageAnalysis("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Expected no error on cancelled context, got %v", err)
	}
	// The cancelled baseline fetch must render as the single inconclusive
	// baseline-failure row, never as a clean scan or a finding.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 row on cancelled context, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected inconclusive status on cancelled context, got %s", result[0].Status)
	}
}

func TestErrorMessageAnalysis__Execute_InvalidURL(t *testing.T) {
	module := NewErrorMessageAnalysis("http://invalid-url-:foo")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Expected no error for invalid target URL, got %v", err)
	}
	// The unparseable target makes the baseline fetch fail: exactly one
	// inconclusive baseline-failure row, never a clean scan.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive row for invalid URL, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected inconclusive status for invalid URL, got %s", result[0].Status)
	}
}

func TestErrorMessageAnalysis__Execute_HTTPError(t *testing.T) {
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

	module := NewErrorMessageAnalysis("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// A uniform-500 target where the baseline itself is an error page yields
	// no attributable signatures: zero rows, never a vulnerable finding.
	if len(result) != 0 {
		t.Errorf("Expected 0 rows when the baseline is already an error page, got %d: %+v", len(result), result)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Unexpected vulnerable row on uniform-500 target: %+v", r)
		}
	}
}
