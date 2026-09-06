package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestSubdomainTakeoverAnalysis_Execute(t *testing.T) {
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

	module := NewSubdomainTakeoverAnalysis("http://example.com")
	module.LookupCNAME = func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no cname in test")
	}

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil {
		t.Log("Expected result, got nil")
	}
}

func TestSubdomainTakeoverAnalysis_Execute_VulnerableTakeover(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`NoSuchBucket`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSubdomainTakeoverAnalysis("http://example.com")
	module.LookupCNAME = func(ctx context.Context, host string) (string, error) {
		if host == "admin.example.com" {
			return "mybucket.s3.amazonaws.com", nil
		}
		return "", errors.New("not found")
	}

	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) == 0 {
		t.Errorf("Expected vulnerable takeover result to be recorded")
	}
}

func TestSubdomainTakeoverAnalysis__Execute_CanceledContext(t *testing.T) {
	module := NewSubdomainTakeoverAnalysis("http://example.com")
	module.LookupCNAME = func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no cname")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestSubdomainTakeoverAnalysis__Execute_InvalidURL(t *testing.T) {
	module := NewSubdomainTakeoverAnalysis("http://invalid-url-:foo")
	module.LookupCNAME = func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no cname")
	}
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestSubdomainTakeoverAnalysis__Execute_HTTPError(t *testing.T) {
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

	module := NewSubdomainTakeoverAnalysis("http://example.com")
	module.LookupCNAME = func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no cname")
	}
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
