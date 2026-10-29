package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestSessionFixationTesting_Execute(t *testing.T) {
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

	module := NewSessionFixationTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("expected an inconclusive skip row when no password form exists, got none")
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("no password form: nothing should be flagged vulnerable, got %#v", r)
		}
	}
}

func TestSessionFixationTesting_Execute_NoVulnerableOnFailedLogin(t *testing.T) {
	// Password form on GET; failed login returns 200 with no Set-Cookie and a
	// failure body — this must NOT produce a session-fixation finding.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><form><input type="password" name="pass"></form><p>Invalid username or password</p></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSessionFixationTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("failed-login 200 with no cookie must not be flagged, got %#v", r)
		}
	}
}

func TestSessionFixationTesting_Execute_DetectsUnrotatedSessionOnSuccess(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><form><input type="password" name="pass"></form><p>Welcome back to your dashboard</p></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSessionFixationTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	found := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("successful login without rotation should be flagged, got %#v", result)
	}
}

func TestSessionFixationTesting_Execute_RotationCookieOn302HopIsVisible(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "/home")
			h.Add("Set-Cookie", "PHPSESSID=brandnewsessionid; Path=/; HttpOnly")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSessionFixationTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("rotation cookie on the 302 hop must prevent a fixation finding, got %#v", r)
		}
	}
}

func TestSessionFixationTesting_Execute_NavWordsWithoutSetCookieNotVulnerable(t *testing.T) {
	// Nav vocabulary (dashboard / my account / logout) on a 200 with no
	// Set-Cookie and no explicit login-confirmation phrase must not be treated
	// as a successful login: the failed-login + nav-words case is not a
	// session-fixation finding.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><form><input type="password" name="pass"></form><nav><a href="/dashboard">Dashboard</a> <a href="/my-account">My Account</a> <a href="/logout">Logout</a></nav></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSessionFixationTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("nav vocabulary without a session cookie must not be flagged, got %#v", r)
		}
	}
}

func TestSessionFixationTesting__Execute_CanceledContext(t *testing.T) {
	module := NewSessionFixationTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestSessionFixationTesting__Execute_InvalidURL(t *testing.T) {
	module := NewSessionFixationTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestSessionFixationTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewSessionFixationTesting("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
