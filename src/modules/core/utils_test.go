package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnsureHTTPPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"ftp://example.com", "ftp://example.com"},
		{"HTTP://example.com", "HTTP://example.com"},
		// A mid-string "://" (query parameter) must not suppress prefixing.
		{"example.com/redirect?next=https://evil.com", "https://example.com/redirect?next=https://evil.com"},
		{"http://example.com/redirect?next=https://evil.com", "http://example.com/redirect?next=https://evil.com"},
		// A bare host:port still gets prefixed (it is not an absolute URL).
		{"127.0.0.1:8080", "https://127.0.0.1:8080"},
		{"example.com:8443/admin", "https://example.com:8443/admin"},
	}

	for _, tt := range tests {
		got := EnsureHTTPPrefix(tt.input)
		if got != tt.expected {
			t.Errorf("EnsureHTTPPrefix(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"http://192.168.1.1:8080/test", "192.168.1.1"},
		{"https://8.8.8.8", "8.8.8.8"},
		{"example.com", ""}, // only parses IP hostnames
		{"", ""},
	}

	for _, tt := range tests {
		got := ExtractHostname(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractHostname(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractTargetHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"http://192.168.1.1:8080/test", "192.168.1.1"},
		{"https://8.8.8.8", "8.8.8.8"},
		{"example.com", "example.com"},
		{"https://sub.victim.com:8443/api/v1", "sub.victim.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := ExtractTargetHost(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractTargetHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewHTTPClient_IndependentCookieJars(t *testing.T) {
	client1 := NewHTTPClient(5 * time.Second)
	client2 := NewHTTPClient(5 * time.Second)

	if client1.Jar == nil || client2.Jar == nil {
		t.Fatal("expected both clients to have initialized CookieJars")
	}

	if client1.Jar == client2.Jar {
		t.Error("expected clients to have separate independent CookieJars, but they share the same instance")
	}
}

// TestTransportTLSVerification exercises the shared default transport against
// a self-signed TLS server: verification is on by default (x509 error), and
// SetTransportInsecureSkipVerify(true) opts into skipping verification. The
// test runs non-parallel and restores the transport so parallel tests that
// swap mocks via SetDefaultTransport are unaffected.
func TestTransportTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	verifyClient := &http.Client{Transport: getDefaultTransport(), Timeout: 10 * time.Second}

	if _, err := verifyClient.Get(srv.URL); err == nil {
		t.Fatal("expected x509 verification error against self-signed server with default transport, got nil")
	}

	SetTransportInsecureSkipVerify(true)
	defer SetTransportInsecureSkipVerify(false)

	// SetTransportInsecureSkipVerify no-ops on non-*http.Transport mocks; if
	// a parallel test left a mock installed the request below would fail —
	// guard by re-checking the concrete type.
	rt := getDefaultTransport()
	if _, ok := rt.(*http.Transport); !ok {
		t.Skip("default transport replaced by a mock; skipping insecure-verify leg")
	}

	skipClient := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	resp, err := skipClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected success with InsecureSkipVerify=true, got: %v", err)
	}
	resp.Body.Close()

	// Toggling back off restores verification on the shared transport.
	SetTransportInsecureSkipVerify(false)
	rt = getDefaultTransport()
	if tr, ok := rt.(*http.Transport); !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected verification re-enabled after SetTransportInsecureSkipVerify(false)")
	}
}
