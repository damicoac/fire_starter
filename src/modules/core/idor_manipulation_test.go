package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIDORManipulation_Execute(t *testing.T) {
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

	module := NewIDORManipulation("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Identical bodies for baseline and every mutated request must not
	// produce IDOR findings; after probing ran, the empty result set is
	// reported as exactly one inconclusive summary row.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive summary row for identical-body responses, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status, got %q", result[0].Status)
	}
}

func TestIDORManipulation_IDKeyMutationFindsVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Query().Get("user_id") == "1" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 7, "username": "victim", "email": "victim@example.com", "phone": "555-0100", "address": "1 Secret Lane", "notes": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "welcome"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewIDORManipulation("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 IDOR finding, got %d", len(result))
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got %q", result[0].Status)
	}
}

func TestIDORManipulation__Execute_CanceledContext(t *testing.T) {
	module := NewIDORManipulation("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestIDORManipulation__Execute_InvalidURL(t *testing.T) {
	module := NewIDORManipulation("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestIDORManipulation__Execute_HTTPError(t *testing.T) {
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

	module := NewIDORManipulation("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// With no 200 responses at all the module must not stay silent: it emits
	// exactly one inconclusive summary row instead of findings.
	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive summary row on uniform 500s, got %d results: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status, got %q", result[0].Status)
	}
}

func TestIDORManipulation_IDMutationPreservesOtherQueryParams(t *testing.T) {
	// With query ?page=2&limit=20&id=42 only the ID-like key may be mutated;
	// pagination/filter context must survive, and the differential must fire
	// via the id mutation alone.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			q := req.URL.Query()
			if q.Get("page") != "2" || q.Get("limit") != "20" {
				t.Errorf("non-ID query params must be preserved, got %q", req.URL.RawQuery)
			}
			switch q.Get("id") {
			case "42":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 42, "username": "self", "email": "me@example.com"}`)),
					Header:     make(http.Header),
				}
			case "1":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 7, "username": "victim", "email": "victim@example.com", "phone": "555-0100", "address": "1 Secret Lane", "notes": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 42, "username": "self", "email": "me@example.com"}`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewIDORManipulation("http://example.com/api/list?page=2&limit=20&id=42")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 IDOR finding via id mutation, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got %q", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "id=1") || !strings.Contains(result[0].Detail, "limit=20") || !strings.Contains(result[0].Detail, "page=2") {
		t.Fatalf("Expected finding URL to carry mutated id with preserved params, got %q", result[0].Detail)
	}
}
