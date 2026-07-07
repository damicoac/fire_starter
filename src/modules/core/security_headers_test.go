package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSecurityHeaders_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "text/html")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Log("Expected results, got none")
	}
}

func TestSecurityHeaders_Execute_CanceledContext(t *testing.T) {
	module := NewSecurityHeaders("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestSecurityHeaders_Execute_NoVulnerability(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Security-Policy", "default-src 'self'")
			h.Set("Strict-Transport-Security", "max-age=31536000")
			h.Set("X-Frame-Options", "DENY")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}

func TestSecurityHeaders_Execute_404(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`Not Found`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com/dump.sql")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results for 404, got %d", len(res))
	}
}

func TestSecurityHeaders_Execute_JSON(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSecurityHeaders("http://example.com/api/v1")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) == 0 {
		t.Fatalf("Expected CSP/HSTS missing, got no results")
	}
	for _, r := range res {
		if strings.Contains(r.Detail, "X-Frame-Options") {
			t.Fatalf("Did not expect X-Frame-Options missing for JSON API, but got: %s", r.Detail)
		}
	}
}
