package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestBrokenObjectLevelAuthorizationBola_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Path == "/api/users/999999999" {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "user not found"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"id": 1, "username": "victim", "email": "victim@example.com", "role": "user", "data": "very_large_user_profile_information_exceeding_length_diff_threshold"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBrokenObjectLevelAuthorizationBola("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected findings for exposed user records, got 0")
	}
}

func TestBrokenObjectLevelAuthorizationBola_LoginRedirectIgnored(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "please login to continue"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewBrokenObjectLevelAuthorizationBola("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) > 0 {
		t.Errorf("Expected login error response to be ignored, got %d findings", len(result))
	}
}

func TestBrokenObjectLevelAuthorizationBola__Execute_CanceledContext(t *testing.T) {
	module := NewBrokenObjectLevelAuthorizationBola("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestBrokenObjectLevelAuthorizationBola__Execute_InvalidURL(t *testing.T) {
	module := NewBrokenObjectLevelAuthorizationBola("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestBrokenObjectLevelAuthorizationBola__Execute_HTTPError(t *testing.T) {
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

	module := NewBrokenObjectLevelAuthorizationBola("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
