package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestReplaciveFuzzing_Execute(t *testing.T) {
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

	module := NewReplaciveFuzzing("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// A healthy endpoint where no payload triggers anything must yield exactly one
	// inconclusive summary row, never silence.
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("expected single inconclusive summary for a clean run, got %#v", result)
	}
}

func TestReplaciveFuzzing_Execute_VulnerableOnPayloadSpecific500(t *testing.T) {
	// Baseline (unmodified URL) responds 200; every mutated payload request 500s.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusInternalServerError
			if req.URL.RawQuery == "" && (req.URL.Path == "" || req.URL.Path == "/") {
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

	module := NewReplaciveFuzzing("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != len(fuzzingStrings) {
		t.Fatalf("expected one finding per payload, got %d results", len(result))
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("expected vulnerable status for payload-specific 500, got %#v", result)
		}
	}
}

func TestReplaciveFuzzing_Execute_Single502StaysInconclusive(t *testing.T) {
	// Baseline responds 200; the first mutated request 502s, but the re-issue
	// of the same payload succeeds: a single unreproduced 502 must be reported
	// as inconclusive (EvidenceStrong), never as a confirmed crash.
	var mutated atomic.Int64
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusOK
			if req.URL.RawQuery == "" && (req.URL.Path == "" || req.URL.Path == "/") {
				status = http.StatusOK
			} else if mutated.Add(1) == 1 {
				status = http.StatusBadGateway
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

	module := NewReplaciveFuzzing("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result for the single 502 sample, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("expected a single unreproduced 502 to stay inconclusive, got %q (%s)", result[0].Status, result[0].Detail)
	}
}

func TestReplaciveFuzzing_Execute_Reproduced502IsVulnerable(t *testing.T) {
	// Baseline responds 200; every mutated request 502s on both the probe and
	// the re-issue: reproducible gateway failures are confirmed worker crashes.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			status := http.StatusBadGateway
			if req.URL.RawQuery == "" && (req.URL.Path == "" || req.URL.Path == "/") {
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

	module := NewReplaciveFuzzing("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != len(fuzzingStrings) {
		t.Fatalf("expected one confirmed finding per payload, got %d results", len(result))
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("expected reproduced 502 to be vulnerable, got %q (%s)", r.Status, r.Detail)
		}
	}
}

func TestReplaciveFuzzing__Execute_CanceledContext(t *testing.T) {
	module := NewReplaciveFuzzing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestReplaciveFuzzing__Execute_InvalidURL(t *testing.T) {
	module := NewReplaciveFuzzing("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestReplaciveFuzzing__Execute_HTTPError(t *testing.T) {
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

	module := NewReplaciveFuzzing("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// A pre-broken endpoint that 500s universally (including its baseline) must not
	// produce vulnerable findings; expect only the inconclusive summary.
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Fatalf("expected single inconclusive result for uniform 500 endpoint, got %#v", result)
	}
}
