package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestInsecureDeserializationTesting_Execute(t *testing.T) {
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

	module := NewInsecureDeserializationTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected no results on a clean target, got %d: %+v", len(result), result)
	}
}

// A probe-produced deserialization exception (marker present in the payload
// response, absent from the benign baseline) is a vulnerable finding.
func TestInsecureDeserializationTesting_JavaExceptionDetected(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			respBody := `{"status": "ok"}`
			if strings.Contains(req.Header.Get("Cookie"), "rO0AB") {
				respBody = "java.io.StreamCorruptedException at java.io.ObjectInputStream.readObject(Native Method)"
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewInsecureDeserializationTesting("http://example.com")

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
	if !strings.Contains(result[0].Detail, "Java Magic Byte") {
		t.Fatalf("expected the Java payload finding, got: %s", result[0].Detail)
	}
}

// A marker that already appears in the ordinary response (javadoc, dependency
// pages, unrelated tracebacks) must not be reported as deserialization proof.
func TestInsecureDeserializationTesting_MarkerInBaselineNotVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`docs: java.io.StreamCorruptedException is thrown by ObjectInputStream`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewInsecureDeserializationTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results when the marker is present in the baseline, got: %s", res.Detail)
		}
	}
}

func TestInsecureDeserializationTesting__Execute_CanceledContext(t *testing.T) {
	module := NewInsecureDeserializationTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestInsecureDeserializationTesting__Execute_InvalidURL(t *testing.T) {
	module := NewInsecureDeserializationTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestInsecureDeserializationTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewInsecureDeserializationTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 inconclusive result when every probe returns HTTP 500, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("expected inconclusive status on HTTP error path, got %q", result[0].Status)
	}
}
