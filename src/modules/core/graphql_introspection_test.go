package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGraphqlIntrospection_Execute(t *testing.T) {
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

	module := NewGraphqlIntrospection("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 results for non-GraphQL 200 responses, got %d: %+v", len(result), result)
	}
}

func TestGraphqlIntrospection_Execute_IntrospectionEnabled(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Mutation"}]}}}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphqlIntrospection("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 vulnerable result for real introspection data, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Errorf("Expected vulnerable status, got %q", result[0].Status)
	}
}

func TestGraphqlIntrospection_Execute_IntrospectionDisabledErrorBody(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema or __type"}]}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphqlIntrospection("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// A hardened server echoing the blocked field name in its error body
	// must not be reported as vulnerable.
	if len(result) != 0 {
		t.Errorf("Expected 0 results for introspection-disabled error body, got %d: %+v", len(result), result)
	}
}

func TestGraphqlIntrospection_Execute_AllProbesFailed(t *testing.T) {
	// Closed server: every probe fails at the transport layer.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	module := NewGraphqlIntrospection(ts.URL)

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 inconclusive result when all probes fail, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected inconclusive status when no endpoint responds, got %q", result[0].Status)
	}
}

func TestGraphqlIntrospection__Execute_CanceledContext(t *testing.T) {
	module := NewGraphqlIntrospection("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestGraphqlIntrospection__Execute_InvalidURL(t *testing.T) {
	module := NewGraphqlIntrospection("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestGraphqlIntrospection__Execute_HTTPError(t *testing.T) {
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

	module := NewGraphqlIntrospection("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Unexpected vulnerable result on HTTP error path: %+v", r)
		}
	}
}
