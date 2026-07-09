package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMassAssignmentInjection_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			bodyStr := string(body)
			if strings.Contains(bodyStr, `"is_admin":true`) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"probe","is_admin":true,"role":"admin"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"username":"probe"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMassAssignmentInjection("http://example.com")
	module.SetThreads(1)

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 || result[0].Status != "vulnerable" {
		t.Fatalf("expected vulnerable result, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_InconclusiveWhenEndpointEchoesUnknownFields(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			respBody := `{"echo":` + string(body) + `}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMassAssignmentInjection("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive status for reflective endpoint, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_NoFindingWhenPrivilegedFieldsNotEchoed(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"id": 42, "username": "safe"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMassAssignmentInjection("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected no findings when privileged fields are not echoed, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_NoFindingWhenValidationRejectsPayload(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "is_admin") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error":"validation failed: is_admin not allowed"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewMassAssignmentInjection("http://example.com")
	module.SetThreads(1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected no findings when server rejects privileged fields, got %#v", result)
	}
}

func TestMassAssignmentInjection__Execute_CanceledContext(t *testing.T) {
	module := NewMassAssignmentInjection("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestMassAssignmentInjection__Execute_InvalidURL(t *testing.T) {
	module := NewMassAssignmentInjection("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestMassAssignmentInjection__Execute_HTTPError(t *testing.T) {
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

	module := NewMassAssignmentInjection("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
