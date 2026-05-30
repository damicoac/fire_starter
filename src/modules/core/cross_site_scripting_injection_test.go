package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestXSSValidator(t *testing.T) {
	v := &XSSValidator{}

	tests := []struct {
		name     string
		body     string
		payload  XSSPayload
		expected bool
	}{
		{
			"HTML Context Success",
			"<div><script>alert(1)</script></div>",
			XSSPayload{"<script>alert(1)</script>", ContextHTML},
			true,
		},
		{
			"HTML Context Failure (encoded)",
			"<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>",
			XSSPayload{"<script>alert(1)</script>", ContextHTML},
			false,
		},
		{
			"Attribute Context Success",
			"<input value=\"\"><script>alert(1)</script>\">",
			XSSPayload{"\"><script>alert(1)</script>", ContextAttribute},
			true,
		},
		{
			"Script Context Success",
			"<script>var x = ''-alert(1)-'';</script>",
			XSSPayload{"'-alert(1)-'", ContextScript},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v.IsVulnerable(tt.body, tt.payload); got != tt.expected {
				t.Errorf("XSSValidator.IsVulnerable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCrossSiteScriptingInjection_Execute(t *testing.T) {
	// Create a mock server that reflects parameters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Discover which parameter has the probe or payload
		q := r.URL.Query()

		// If it's a probe (from DiscoverReflection)
		for _, vals := range q {
			for _, val := range vals {
				if strings.HasPrefix(val, "PROBE") {
					// Reflect the probe in HTML context
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<div>" + val + "</div>"))
					return
				}
			}
		}

		// If it's a payload (from testContextPayload)
		if val := q.Get("q"); val != "" {
			// Mock vulnerability: reflect back unescaped
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<div>" + val + "</div>"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Safe"))
	}))
	defer server.Close()

	m := NewCrossSiteScriptingInjection(server.URL + "?q=test")
	results, err := m.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, res := range results {
		if res.Status == "vulnerable" {
			found = true
			if !strings.Contains(res.Detail, "vulnerable") && !strings.Contains(res.Detail, "XSS found") {
				t.Errorf("Unexpected detail: %s", res.Detail)
			}
		}
	}

	if !found {
		t.Error("Expected to find XSS vulnerability, but none found")
	}
}

func TestCrossSiteScriptingInjection__Execute_CanceledContext(t *testing.T) {
	m := NewCrossSiteScriptingInjection("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = m.Execute(ctx)
}

func TestCrossSiteScriptingInjection__Execute_InvalidURL(t *testing.T) {
	m := NewCrossSiteScriptingInjection("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = m.Execute(ctx)
}

func TestCrossSiteScriptingInjection__Execute_HTTPError(t *testing.T) {
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

	m := NewCrossSiteScriptingInjection("http://example.com")
	ctx := context.Background()
	_, _ = m.Execute(ctx)
}
