package core

import (
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
