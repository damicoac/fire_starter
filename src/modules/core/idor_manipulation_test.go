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
	// user_id is a real ID-like parameter: mutating it to two different
	// values returns other users' records (both differ from the baseline),
	// so the normalized differential reproduces across mutated values and
	// the finding is confirmed.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.URL.Query().Get("user_id") {
			case "1":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 7, "username": "victim", "email": "victim@example.com", "phone": "555-0100", "address": "1 Secret Lane", "notes": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)),
					Header:     make(http.Header),
				}
			case "0":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 8, "username": "other", "email": "other@example.com", "phone": "555-0199", "address": "9 Other Lane", "notes": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"}`)),
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

	module := NewIDORManipulation("http://example.com/api/users?user_id=42")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Payloads 1 and 0 both reach foreign records (differential reproduced
	// with a different mutated value); every other payload matches baseline.
	if len(result) != 2 {
		t.Fatalf("Expected exactly 2 IDOR findings, got %d: %+v", len(result), result)
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected vulnerable status, got %q", r.Status)
		}
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
			case "0":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id": 8, "username": "other", "email": "other@example.com", "phone": "555-0199", "address": "9 Other Lane", "notes": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"}`)),
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

	// Mutating id to 1 and 0 both reach foreign records, and the differential
	// reproduces on a second request with a different mutated value for each.
	if len(result) != 2 {
		t.Fatalf("Expected exactly 2 IDOR findings via id mutation, got %d: %+v", len(result), result)
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected vulnerable status, got %q", r.Status)
		}
		if !strings.Contains(r.Detail, "limit=20") || !strings.Contains(r.Detail, "page=2") || !strings.Contains(r.Detail, "id=") {
			t.Fatalf("Expected finding URL to carry mutated id with preserved params, got %q", r.Detail)
		}
	}
}
