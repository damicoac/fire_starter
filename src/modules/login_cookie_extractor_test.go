package modules

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestLoginCookieExtractor_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			header := make(http.Header)
			header.Add("Set-Cookie", "session_id=12345; Path=/; HttpOnly")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     header,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewLoginCookieExtractor("http://example.com/login", "admin", "password")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result == nil || len(result) == 0 {
		t.Fatal("Expected result, got nil or empty")
	}

	if result[0]["status"] != "success" {
		t.Errorf("Expected status success, got %v", result[0]["status"])
	}
}
