package modules

import (
	"testing"
	"time"
)

func TestNewHTTPClient(t *testing.T) {
	timeout := 5 * time.Second
	client := NewHTTPClient(timeout)

	if client.Timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, client.Timeout)
	}

	if client.Transport == nil {
		t.Error("Expected transport to be set")
	}
}

func TestEnsureHTTPPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "http://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	}

	for _, tt := range tests {
		actual := EnsureHTTPPrefix(tt.input)
		if actual != tt.expected {
			t.Errorf("EnsureHTTPPrefix(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}
