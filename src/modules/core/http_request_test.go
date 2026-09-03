package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestHTTPRequestModule_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	headers := map[string]string{
		"Authorization": "Bearer test-token",
	}
	module := NewHTTPRequestModule("http://example.com/api/test", "POST", `{"query":"test"}`, headers)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusCode, ok := result["status_code"].(int)
	if !ok || statusCode != http.StatusOK {
		t.Errorf("expected status_code 200, got %v", result["status_code"])
	}

	body, ok := result["body"].(string)
	if !ok || body != `{"status": "ok"}` {
		t.Errorf("expected body `{\"status\": \"ok\"}`, got %v", result["body"])
	}
}

func TestHTTPRequestModule_Registry(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"user":"admin"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	factory, ok := GetModuleFactory("http_request")
	if !ok {
		t.Fatal("expected http_request module to be registered")
	}

	mod, err := factory(map[string]any{
		"url":    "http://example.com/profile",
		"method": "GET",
	}, func(string) {})
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}

	res, err := mod.Execute(context.Background())
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	resMap, ok := res.(map[string]any)
	if !ok || resMap["status_code"] != 200 {
		t.Errorf("unexpected execute result: %+v", res)
	}
}
