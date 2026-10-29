package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPasswordSpraying_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 results for identical failed-login responses, got %d: %+v", len(result), result)
	}
}

func TestPasswordSpraying_Execute_SuccessfulLogin(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			hdr := make(http.Header)
			reqBody := ""
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				reqBody = string(body)
			}
			if reqBody == "username=admin&password=Password1!" {
				hdr.Set("Set-Cookie", "session=abc123")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(strings.Repeat("welcome to the admin dashboard. ", 40))),
					Header:     hdr,
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("invalid credentials")),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")

	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected exactly 1 vulnerable result for successful login, got %d: %+v", len(results), results)
	}
	if results[0].Status != "vulnerable" {
		t.Errorf("Expected vulnerable status, got %q", results[0].Status)
	}
	if !strings.Contains(results[0].Detail, "admin") {
		t.Errorf("Expected detail to name the successful username, got %q", results[0].Detail)
	}
}

func TestPasswordSpraying_Execute_RedirectSuccess(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			hdr := make(http.Header)
			reqBody := ""
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				reqBody = string(body)
			}
			if reqBody == "username=admin&password=Password1!" {
				hdr.Set("Location", "/dashboard")
				return &http.Response{
					StatusCode: http.StatusFound,
					Body:       io.NopCloser(bytes.NewBufferString("")),
					Header:     hdr,
				}
			}
			hdr.Set("Location", "/login")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")

	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Redirect to /dashboard differs from the baseline's /login redirect → success;
	// identical /login redirects must not be judged as successful logins.
	if len(results) != 1 {
		t.Fatalf("Expected exactly 1 vulnerable result for divergent redirect, got %d: %+v", len(results), results)
	}
	if results[0].Status != "vulnerable" {
		t.Errorf("Expected vulnerable status, got %q", results[0].Status)
	}
}

// A success redirect to "/login/" must compare equal to the baseline's
// failed-login "/login" redirect (normalized paths), so no finding is emitted.
func TestPasswordSpraying_Execute_RedirectTrailingSlashNotSuccess(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			hdr := make(http.Header)
			reqBody := ""
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				reqBody = string(body)
			}
			if reqBody == "username=admin&password=Password1!" {
				hdr.Set("Location", "/login/")
				return &http.Response{
					StatusCode: http.StatusFound,
					Body:       io.NopCloser(bytes.NewBufferString("")),
					Header:     hdr,
				}
			}
			hdr.Set("Location", "/login")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Expected 0 results when success redirect resolves to the same failed-login path, got %d: %+v", len(results), results)
	}
}

// The bare word "attempt" on a genuine success page must not trigger the
// lockout abort; only co-occurrence with lockout/throttle markers counts.
func TestPasswordSpraying_Execute_AttemptWordAloneDoesNotAbort(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			hdr := make(http.Header)
			reqBody := ""
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				reqBody = string(body)
			}
			if reqBody == "username=admin&password=Password1!" {
				hdr.Set("Set-Cookie", "session=abc123")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("<html>Welcome admin, your login attempt was successful. Dashboard loads here with plenty of extra content to differ from the failure page.</html>")),
					Header:     hdr,
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("invalid credentials, please retry")),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 1 || results[0].Status != "vulnerable" {
		t.Fatalf("Expected exactly 1 vulnerable result for genuine success containing the word 'attempt', got: %+v", results)
	}
}

func TestPasswordSpraying_Execute_LockoutAborts(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			hdr := make(http.Header)
			reqBody := ""
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				reqBody = string(body)
			}
			if reqBody == "username=admin&password=Password1!" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("Your account has been temporarily locked due to too many failed attempts")),
					Header:     hdr,
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("invalid credentials")),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewPasswordSpraying("http://example.com")

	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, r := range results {
		if r.Status == "vulnerable" {
			t.Errorf("Lockout page must never be judged a successful login: %+v", r)
		}
	}
	foundInconclusive := false
	for _, r := range results {
		if r.Status == "inconclusive" {
			foundInconclusive = true
		}
	}
	if !foundInconclusive {
		t.Errorf("Expected an inconclusive lockout result, got %+v", results)
	}
}

func TestPasswordSpraying__Execute_CanceledContext(t *testing.T) {
	module := NewPasswordSpraying("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestPasswordSpraying__Execute_InvalidURL(t *testing.T) {
	module := NewPasswordSpraying("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestPasswordSpraying__Execute_HTTPError(t *testing.T) {
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

	module := NewPasswordSpraying("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
