package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
	foundInconclusive := false
	for _, res := range result {
		if res.Status == "vulnerable" {
			foundVulnerable = true
		}
		if res.Status == "inconclusive" {
			foundInconclusive = true
		}
	}

	if !foundVulnerable {
		t.Error("expected at least one vulnerable result for the 200 OK ListBucketResult S3 bucket")
	}
	if !foundInconclusive {
		t.Error("expected at least one inconclusive result for the 403 Forbidden buckets")
	}
}

func TestCloudStorageFuzzing_GCS_ListableBucket(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Host == "storage.googleapis.com" && req.URL.Path == "/example-public/" {
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

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundGCSVulnerable := false
	for _, res := range result {
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "GCS") {
			foundGCSVulnerable = true
		}
		if res.Status == "vulnerable" && !strings.Contains(res.Detail, "GCS") {
			t.Errorf("unexpected non-GCS vulnerable result: %+v", res)
		}
	}
	if !foundGCSVulnerable {
		t.Error("expected a vulnerable result for the publicly listable GCS bucket")
	}
}

func TestCloudStorageFuzzing_Azure_PublicContainer(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.HasSuffix(req.URL.Host, ".blob.core.windows.net") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<?xml version="1.0"?><EnumerationResults><Blobs></Blobs></EnumerationResults>`)),
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

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundAzureVulnerable := false
	for _, res := range result {
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "Azure") {
			foundAzureVulnerable = true
		}
		if res.Status == "vulnerable" && !strings.Contains(res.Detail, "Azure") {
			t.Errorf("unexpected non-Azure vulnerable result: %+v", res)
		}
	}
	if !foundAzureVulnerable {
		t.Error("expected a vulnerable result for the publicly readable Azure blob container")
	}
}

func TestCloudStorageFuzzing_S3_200WithoutMarker(t *testing.T) {
	// A proxy/WAF answering 200 for everything must not be reported as a
	// publicly readable bucket.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"hello":"world"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCloudStorageFuzzing("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("200 without ListBucketResult must not be vulnerable: %+v", res)
		}
	}
	if len(result) == 0 {
		t.Fatal("expected inconclusive rows for unverified S3 200 responses, got none")
	}
}

func TestCloudStorageFuzzing_AzureContainerNotFoundSkipped(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.HasSuffix(req.URL.Host, ".blob.core.windows.net") {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`ContainerNotFound`)),
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

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("non-existent Azure container must not be reported vulnerable: %+v", res)
		}
		if strings.Contains(res.Detail, "blob.core.windows.net") {
			t.Errorf("missing Azure container should be skipped, got result: %+v", res)
		}
	}
	if len(result) == 0 {
		t.Fatal("expected inconclusive rows for the 403 S3/GCS buckets, got none")
	}
}

func TestCloudStorageFuzzing_AllProbesFail(t *testing.T) {
	cleanup := SetDefaultTransport(cloudStorageErrTransport{})
	defer cleanup()

	module := NewCloudStorageFuzzing("http://example.com")

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive summary when all probes fail, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("Expected status %q when all probes fail, got %q", "inconclusive", result[0].Status)
	}
	if !strings.Contains(result[0].Detail, "probes failed") {
		t.Errorf("Expected detail to carry the probe failure, got %q", result[0].Detail)
	}
}

// cloudStorageErrTransport is a RoundTripper that always fails, used to
// exercise transport-failure handling.
type cloudStorageErrTransport struct{}

func (cloudStorageErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused by mock")
}

func TestCloudStorageFuzzing_Execute_CanceledContext(t *testing.T) {
	module := NewCloudStorageFuzzing("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestCloudStorageFuzzing_Execute_HTTPError(t *testing.T) {
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

	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// 500 responses classify nothing; the run must not look silently clean.
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Errorf("Expected 1 inconclusive summary for unclassifiable 500 responses, got %+v", result)
	}
}
