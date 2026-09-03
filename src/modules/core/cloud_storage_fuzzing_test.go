package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestCloudStorageFuzzing_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Host == "example-public.s3.amazonaws.com" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<?xml version="1.0"?><ListBucketResult></ListBucketResult>`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`AccessDenied`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCloudStorageFuzzing("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundVulnerable := false
	foundInfo := false
	for _, res := range result {
		if res.Status == "vulnerable" {
			foundVulnerable = true
		}
		if res.Status == "info" {
			foundInfo = true
		}
	}

	if !foundVulnerable {
		t.Error("expected at least one vulnerable result for 200 OK bucket")
	}
	if !foundInfo {
		t.Error("expected at least one info result for 403 Forbidden bucket")
	}
}

func TestCloudStorageFuzzing__Execute_CanceledContext(t *testing.T) {
	module := NewCloudStorageFuzzing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestCloudStorageFuzzing__Execute_InvalidURL(t *testing.T) {
	module := NewCloudStorageFuzzing("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestCloudStorageFuzzing__Execute_HTTPError(t *testing.T) {
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

	module := NewCloudStorageFuzzing("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
