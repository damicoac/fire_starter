package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
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

func TestHTTPRequestModule_CookieMerge(t *testing.T) {
	var seenCookie []string
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			seenCookie = req.Header.Values("Cookie")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("ok")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	headers := map[string]string{"Cookie": "user=1"}
	module := NewHTTPRequestModule("http://example.com/", "GET", "", headers)
	module.SetCookies("session=abc")

	if _, err := module.Execute(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(seenCookie) != 2 {
		t.Fatalf("Expected caller and session Cookie values to both be sent, got %v", seenCookie)
	}
}

func TestHTTPRequestModule_SessionCookieOnly(t *testing.T) {
	var seenCookie []string
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			seenCookie = req.Header.Values("Cookie")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("ok")),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHTTPRequestModule("http://example.com/", "GET", "", nil)
	module.SetCookies("session=abc")

	if _, err := module.Execute(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(seenCookie) != 1 || seenCookie[0] != "session=abc" {
		t.Fatalf("Expected single session Cookie header, got %v", seenCookie)
	}
}

type httpRequestFailingBody struct{}

func (httpRequestFailingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (httpRequestFailingBody) Close() error             { return nil }

func TestHTTPRequestModule_BodyReadErrorPropagates(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(httpRequestFailingBody{}),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHTTPRequestModule("http://example.com/", "GET", "", nil)

	_, err := module.Execute(context.Background())
	if err == nil {
		t.Fatal("Expected body read error to propagate, got nil")
	}
}

func TestHTTPRequestModule_TruncationMarker(t *testing.T) {
	payload := strings.Repeat("A", MaxResponseBodyBytes+16)
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(payload)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHTTPRequestModule("http://example.com/", "GET", "", nil)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	truncated, ok := result["truncated"].(bool)
	if !ok || !truncated {
		t.Errorf("Expected truncated=true for oversized body, got %v", result["truncated"])
	}
	if body, _ := result["body"].(string); len(body) != MaxResponseBodyBytes {
		t.Errorf("Expected body capped at %d bytes, got %d", MaxResponseBodyBytes, len(body))
	}
}
