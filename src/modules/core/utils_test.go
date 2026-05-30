package core

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
		{"", "http://"},
	}

	for _, tt := range tests {
		actual := EnsureHTTPPrefix(tt.input)
		if actual != tt.expected {
			t.Errorf("EnsureHTTPPrefix(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "plain ipv4", input: "192.168.1.10", expected: "192.168.1.10"},
		{name: "url with ipv4", input: "http://10.0.0.5:8080/path", expected: "10.0.0.5"},
		{name: "hostname", input: "example.com", expected: ""},
		{name: "url hostname", input: "https://example.com/test", expected: ""},
		{name: "empty", input: "   ", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ExtractHostname(tt.input)
			if actual != tt.expected {
				t.Errorf("ExtractHostname(%q) = %q, expected %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestNewHTTPClient_ZeroTimeout(t *testing.T) {
	client := NewHTTPClient(0)
	if client.Timeout != 0 {
		t.Errorf("Expected 0 timeout, got %v", client.Timeout)
	}
}
