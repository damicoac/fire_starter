package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestRateLimitProbing_Execute(t *testing.T) {
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

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 || result[0].Status != "vulnerable" {
		t.Fatalf("expected vulnerable status when no throttling is observed, got %#v", result)
	}
}

func TestRateLimitProbing_Execute_SecureWhenCorroboratedThrottleDetected(t *testing.T) {
	requestCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			requestCount++
			headers := make(http.Header)
			status := http.StatusOK

			switch {
			case requestCount > 20 && requestCount <= 40:
				status = http.StatusTooManyRequests
				headers.Set("Retry-After", "1")
			case requestCount > 40 && requestCount <= 50:
				status = http.StatusOK
			case requestCount > 50:
				status = http.StatusOK
			}

			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     headers,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) == 0 || results[0].Status != "secure" {
		t.Fatalf("expected secure status when corroborated throttling is observed, got %#v", results)
	}
}

func TestRateLimitProbing_Execute_SecureWhenFullyThrottled(t *testing.T) {
	// A limiter that 429s the entire burst (successCount == 0) used to fall through to
	// the "unstable" bucket; throttle domination plus recovery corroboration must win.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			headers := make(http.Header)
			headers.Set("Retry-After", "1")
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "rate limited"}`)),
				Header:     headers,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) == 0 || results[0].Status != "secure" {
		t.Fatalf("expected secure status for fully-throttled burst, got %#v", results)
	}
}

func TestRateLimitProbing_Execute_InconclusiveWhenBaselineFails(t *testing.T) {
	// nil response from RoundTrip surfaces as a transport error in Client.Do.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) != 1 || results[0].Status != "inconclusive" {
		t.Fatalf("expected single inconclusive result when baseline fails, got %#v", results)
	}
}

func TestRateLimitProbing_Execute_InconclusiveWhenAuthProtected(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "auth required"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) == 0 || results[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status for auth-protected endpoint, got %#v", results)
	}
}

func TestRateLimitProbing_Execute_InconclusiveWhenWeakSignalOnly(t *testing.T) {
	requestCount := 0
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			requestCount++
			headers := make(http.Header)
			status := http.StatusOK
			if requestCount == 2 {
				status = http.StatusTooManyRequests
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     headers,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewRateLimitProbing("http://example.com")
	module.SetThreads(1)

	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) == 0 || results[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status for weak/unconfirmed throttling signals, got %#v", results)
	}
}

func TestRateLimitProbing__Execute_CanceledContext(t *testing.T) {
	module := NewRateLimitProbing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestRateLimitProbing__Execute_InvalidURL(t *testing.T) {
	module := NewRateLimitProbing("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestRateLimitProbing__Execute_HTTPError(t *testing.T) {
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

	module := NewRateLimitProbing("http://example.com")
	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// A uniform-500 target yields an unstable burst: exactly one summary row
	// and it must be inconclusive, never vulnerable or secure.
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 summary result on a uniform-500 target, got %d: %+v", len(results), results)
	}
	if results[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status on a uniform-500 target, got %q (%s)", results[0].Status, results[0].Detail)
	}
}
