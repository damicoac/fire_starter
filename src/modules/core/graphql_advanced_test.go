package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGraphQLAdvanced_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected batching results, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Errorf("Expected vulnerable status for batched array response, got %q", r.Status)
		}
	}
}

// An empty `"errors": []` array is spec-permissive and must not block a
// legitimate batching finding.
func TestGraphQLAdvanced_Execute_BatchingWithEmptyErrorArrays(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"data":{"__typename":"Query"},"errors":[]},{"data":{"__typename":"Query"},"errors":[]}]`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "batching") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected a vulnerable batching finding despite empty error arrays, got: %+v", result)
	}
}

func TestGraphQLAdvanced_Execute_AliasData(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"a1":"Query","a2":"Query","a3":"Query","a4":"Query","a5":"Query"}}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected alias-batching results, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Errorf("Expected vulnerable status for alias data response, got %q", r.Status)
		}
	}
}

func TestGraphQLAdvanced_Execute_RejectionError(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"errors":[{"message":"Cannot query field 'a5' on type 'Query'."}]}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// A rejecting server echoing the alias name in its validation error
	// must not be reported as vulnerable.
	if len(result) != 0 {
		t.Errorf("Expected 0 results for rejection error body, got %d: %+v", len(result), result)
	}
}

func TestGraphQLAdvanced_Execute_AllProbesFailed(t *testing.T) {
	// Closed server: every probe fails at the transport layer.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	module := NewGraphQLAdvanced(ts.URL)
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

func TestGraphQLAdvanced_Execute_CanceledContext(t *testing.T) {
	module := NewGraphQLAdvanced("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestGraphQLAdvanced_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "batching not supported"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGraphQLAdvanced("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}
