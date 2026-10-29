package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHttpParameterPollutionHpp_Execute(t *testing.T) {
	// Uniform 200 with no parameter-sensitive behavior: expect zero findings.
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

	module := NewHttpParameterPollutionHpp("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 results on clean target, got %d: %+v", len(result), result)
	}
}

// TestHttpParameterPollutionHpp_ConcatenationVulnerable pins the positive
// concatenation judge: a server that joins the original and polluted values in
// the body (in either order) is vulnerable.
func TestHttpParameterPollutionHpp_ConcatenationVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			// Server concatenates repeated "id" values: id=1&id=polluted -> "1,polluted_value_12345".
			if len(req.URL.Query()["id"]) > 1 {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"result": "1,polluted_value_12345"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpParameterPollutionHpp("http://example.com/?id=1")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a vulnerable HPP finding on concatenating server, got %+v", result)
	}
}

func TestHttpParameterPollutionHpp__Execute_CanceledContext(t *testing.T) {
	module := NewHttpParameterPollutionHpp("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestHttpParameterPollutionHpp__Execute_InvalidURL(t *testing.T) {
	module := NewHttpParameterPollutionHpp("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

// TestHttpParameterPollutionHpp__Execute_HTTPError pins the differential
// requirement: a uniform 500 on every request (including the unpolluted
// baseline) must NOT be reported as HPP.
func TestHttpParameterPollutionHpp__Execute_HTTPError(t *testing.T) {
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

	module := NewHttpParameterPollutionHpp("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("uniform-500 target must yield 0 HPP findings (any 500 alone is not proof), got %d: %+v", len(result), result)
	}
	for _, r := range result {
		if strings.Contains(r.Status, "vulnerable") {
			t.Fatalf("unexpected vulnerable finding on uniform-500 target: %+v", r)
		}
	}
}
