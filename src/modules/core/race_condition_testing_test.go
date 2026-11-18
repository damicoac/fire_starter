package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRaceConditionTesting_Execute(t *testing.T) {
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

	module := NewRaceConditionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Uniform all-200 outcomes carry no differential evidence for a module that
	// cannot inspect server-side state: expect a single inconclusive row.
	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result for uniform 200 responses, got %#v", result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status for uniform 200 responses, got %s", result[0].Status)
	}
}

func TestRaceConditionTesting_Execute_VulnerableOnInconsistentEnforcement(t *testing.T) {
	// Textbook race signature: some identical requests accepted (200), others
	// rejected (400) — inconsistent enforcement of a state-changing endpoint.
	// The mix is periodic so it reproduces on the confirming second volley.
	var requestCount int32
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusBadRequest
			if atomic.AddInt32(&requestCount, 1)%4 == 1 {
				status = http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "done"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRaceConditionTesting("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status != "vulnerable" {
		t.Fatalf("expected single vulnerable result for mixed 200/400 enforcement, got %#v", result)
	}
}

func TestRaceConditionTesting_Execute_NoFindingForRedirectMix(t *testing.T) {
	// A 200/301 mix carries no state-change evidence and must not be reported as a race.
	var requestCount int32
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusMovedPermanently
			if atomic.AddInt32(&requestCount, 1) <= 10 {
				status = http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRaceConditionTesting("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status == "vulnerable" {
		t.Fatalf("expected non-vulnerable result for 200/301 mix, got %#v", result)
	}
}

func TestRaceConditionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewRaceConditionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestRaceConditionTesting__Execute_InvalidURL(t *testing.T) {
	module := NewRaceConditionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestRaceConditionTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewRaceConditionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// 500s are excluded uniformly with 429/502/503/504, so a uniform-500 endpoint
	// yields no counted responses and must not be reported as a race.
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("expected single inconclusive result for uniform 500 responses, got %#v", result)
	}
}

func TestRaceConditionTesting_Execute_AllProbesErrored(t *testing.T) {
	// A volley where every probe fails at the transport layer must yield an
	// explicit inconclusive row naming the failures, not look clean.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil // transport failure
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRaceConditionTesting("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result for an all-errored volley, got %#v", result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status for all-errored volley, got %q", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "failed") {
		t.Fatalf("expected detail to name probe failures, got %q", result[0].Detail)
	}
}

func TestRaceConditionTesting_Execute_UnreproducedMixStaysInconclusive(t *testing.T) {
	// A mixed 2xx/4xx outcome that appears only in the first volley and not in
	// the confirming second volley must not be reported as a confirmed race.
	var requestCount int32
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusBadRequest
			// Mix only during the first 20 requests (first volley); the
			// second volley is uniform 400s.
			if atomic.AddInt32(&requestCount, 1) <= 3 {
				status = http.StatusOK
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "done"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRaceConditionTesting("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result for an unreproduced mix, got %#v", result)
	}
	if result[0].Status == "vulnerable" {
		t.Fatalf("unreproduced mix must not be a confirmed race, got %#v", result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive for unreproduced mix, got %q", result[0].Status)
	}
}
