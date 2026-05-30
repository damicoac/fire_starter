// src/modules/threat_monitoring_testing_test.go
package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestThreatMonitoringDetection(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		if atomic.LoadInt32(&requestCount) > 10 {
			// Simulate WAF blocking after 10 requests
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewThreatMonitoringTesting(server.URL)
	tester.SetBurstCount(20) // send 20 requests
	results, err := tester.Execute(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	if results[0].Status != "secure" {
		t.Errorf("Expected status secure (monitoring detected), got %s", results[0].Status)
	}
}

func TestThreatMonitoringVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 200 OK regardless of request count
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewThreatMonitoringTesting(server.URL)
	tester.SetBurstCount(20) // send 20 requests
	results, err := tester.Execute(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	if results[0].Status != "vulnerable" {
		t.Errorf("Expected status vulnerable (no monitoring detected), got %s", results[0].Status)
	}
}

func TestThreatMonitoringDetection_Execute_CanceledContext(t *testing.T) {
	tester := NewThreatMonitoringTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = tester.Execute(ctx)
}

func TestThreatMonitoringDetection_Execute_InvalidURL(t *testing.T) {
	tester := NewThreatMonitoringTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = tester.Execute(ctx)
}

func TestThreatMonitoringDetection_Execute_HTTPError(t *testing.T) {
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

	tester := NewThreatMonitoringTesting("http://example.com")
	ctx := context.Background()
	_, _ = tester.Execute(ctx)
}
