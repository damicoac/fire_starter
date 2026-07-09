package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMassAssignmentInjection_Execute_CausalPersistenceConfirmed(t *testing.T) {
	persistedByMarker := map[string]bool{}
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				marker := req.URL.Query().Get("firestarter_probe_marker")
				if persistedByMarker[marker] {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `","is_admin":true,"role":"admin"}`)),
						Header:     make(http.Header),
					}
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `"}`)),
					Header:     make(http.Header),
				}
			}

			body, _ := io.ReadAll(req.Body)
			payload := map[string]any{}
			_ = json.Unmarshal(body, &payload)
			marker, _ := payload["username"].(string)

			if strings.Contains(string(body), `"is_admin":true`) || strings.Contains(string(body), `"isAdmin":true`) || strings.Contains(string(body), `"role":"admin"`) || strings.Contains(string(body), `"permissions":"all"`) {
				persistedByMarker[marker] = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `","accepted":true}`)),
					Header:     make(http.Header),
				}
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `"}`)),
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

	if len(result) == 0 || result[0].Status != "vulnerable" {
		t.Fatalf("expected vulnerable result with causal persisted-state proof, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_InconclusiveWhenEndpointEchoesUnknownFields(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				marker := req.URL.Query().Get("firestarter_probe_marker")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `"}`)),
					Header:     make(http.Header),
				}
			}
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

func TestMassAssignmentInjection_Execute_SecureWhenVerificationNegatesPersistence(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				marker := req.URL.Query().Get("firestarter_probe_marker")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `"}`)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), `"is_admin":true`) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"message":"accepted"}`)),
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
	if len(result) == 0 || result[0].Status != "secure" {
		t.Fatalf("expected secure status when verification disproves persistence, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_NoFindingWhenPrivilegedFieldsNotEchoed(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				marker := req.URL.Query().Get("firestarter_probe_marker")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id":42,"username":"` + marker + `"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"id":42,"username":"safe"}`)),
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
		t.Fatalf("expected no findings when no anomaly is present, got %#v", result)
	}
}

func TestMassAssignmentInjection_Execute_NoFindingWhenValidationRejectsPayload(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				marker := req.URL.Query().Get("firestarter_probe_marker")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"username":"` + marker + `"}`)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "is_admin") || strings.Contains(string(body), "isAdmin") || strings.Contains(string(body), "role") || strings.Contains(string(body), "permissions") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error":"validation failed: privileged fields not allowed"}`)),
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
