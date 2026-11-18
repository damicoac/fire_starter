package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A catch-all 200 that echoes the same body for uploads and fetches proves
// acceptance but not storage: the module must report inconclusive rows, never
// a vulnerable finding without the canary served back.
func TestUnrestrictedFileUpload_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "success"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected results, got none")
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status (storage unverified), got: %s", result[0].Status)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("catch-all 200 without storage proof must not be judged vulnerable: %#v", r)
		}
	}
}

// When the follow-up GET returns the exact canary content, the upload is
// storage-verified and flagged vulnerable.
func TestUnrestrictedFileUpload_Execute_StorageVerified(t *testing.T) {
	phpCanary := "<?php echo 'vuln'; ?>"
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == http.MethodGet {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(phpCanary)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"stored": true}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "test.php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a storage-verified vulnerable finding for test.php, got %+v", result)
	}
}

// A 2xx upload whose stored file cannot be retrieved (404 on every served
// path) must stay inconclusive.
func TestUnrestrictedFileUpload_Execute_NoStorageProof(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == http.MethodGet {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`not found`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"stored": true}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected inconclusive rows for accepted-but-unverified uploads, got none")
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("upload without storage proof must not be judged vulnerable: %#v", r)
		}
		if r.Status != "inconclusive" || !strings.Contains(r.Detail, "storage unverified") {
			t.Fatalf("expected inconclusive storage-unverified row, got: %+v", r)
		}
	}
}

func TestUnrestrictedFileUpload_Execute_CanceledContext(t *testing.T) {
	module := NewUnrestrictedFileUpload("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestUnrestrictedFileUpload_Execute_HTTPError(t *testing.T) {
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

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) != 1 {
		t.Fatalf("Expected single inconclusive summary result, got %d", len(res))
	}
	if res[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive status on 500 error, got: %s", res[0].Status)
	}
}

func TestUnrestrictedFileUpload_Execute_RejectionBodyOn200(t *testing.T) {
	// A 200 with a differently-worded rejection body must not be judged
	// vulnerable; only the inconclusive summary remains.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"success":false,"message":"file extension rejected"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewUnrestrictedFileUpload("http://example.com")
	ctx := context.Background()
	res, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("Expected no vulnerable findings on rejection body, got %#v", res)
		}
	}
}
