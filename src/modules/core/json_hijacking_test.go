package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestJsonHijackingTest_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`["item1", "item2"]`)),
				Header:     header,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJsonHijackingTest("http://example.com")

	// Override the client to use the mock transport
	module.Client.Transport = mockTransport

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected result indicating vulnerability, got none")
	}

	if result[0].Status != "vulnerable" {
		t.Fatalf("Expected vulnerable status, got: %s", result[0].Status)
	}
}

func TestJsonHijackingTest__Execute_CanceledContext(t *testing.T) {
	module := NewJsonHijackingTest("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestJsonHijackingTest__Execute_InvalidURL(t *testing.T) {
	module := NewJsonHijackingTest("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestJsonHijackingTest__Execute_HTTPError(t *testing.T) {
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

	module := NewJsonHijackingTest("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected no findings for a 500-only target, got %#v", result)
	}
}

func TestJsonHijackingTest_Execute_NoFindingOnNullBody(t *testing.T) {
	// `null` unmarshals into a nil slice: no records are exposed.
	result := runJSONHijackingWithBody(t, `null`)
	if len(result) != 0 {
		t.Fatalf("Expected no findings for null body, got %#v", result)
	}
}

func TestJsonHijackingTest_Execute_NoFindingOnEmptyArray(t *testing.T) {
	// An empty top-level array exposes no records.
	result := runJSONHijackingWithBody(t, `[]`)
	if len(result) != 0 {
		t.Fatalf("Expected no findings for empty array body, got %#v", result)
	}
}

func TestJsonHijackingTest_Execute_NoFindingOnObjectBody(t *testing.T) {
	// A top-level JSON object is not hijackable via the legacy <script> array
	// constructor trick.
	result := runJSONHijackingWithBody(t, `{"a":1}`)
	if len(result) != 0 {
		t.Fatalf("Expected no findings for object body, got %#v", result)
	}
}

func runJSONHijackingWithBody(t *testing.T, body string) []JsonHijackingTestResult {
	t.Helper()
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     header,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJsonHijackingTest("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	return result
}

func TestJsonHijackingTest_Execute_NoFindingOnUnauthenticatedArray(t *testing.T) {
	// A 401 array body (or any non-2xx / non-JSON response) cannot represent the
	// victim's authenticated data and must not be judged vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`["unauthorized"]`)),
				Header:     header,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJsonHijackingTest("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("Expected no findings for unauthenticated array body, got %#v", result)
	}
}

func TestJsonHijackingTest_Execute_NoFindingOnNonJSONContentType(t *testing.T) {
	// Top-level-array-looking bodies served as text/html (e.g. error pages) are
	// not JSON hijacking evidence.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			header.Set("Content-Type", "text/html")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`["not json"]`)),
				Header:     header,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewJsonHijackingTest("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("Expected no findings for non-JSON content type, got %#v", result)
	}
}
