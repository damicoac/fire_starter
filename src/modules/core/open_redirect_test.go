package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestOpenRedirect_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			// Echo the injected payload back as the Location header, mimicking
			// an endpoint that redirects to the supplied value verbatim.
			loc := ""
			for _, vs := range req.URL.Query() {
				if len(vs) > 0 {
					loc = vs[0]
					break
				}
			}
			h := make(http.Header)
			h.Set("Location", loc)
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOpenRedirect("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// 5 endpoints x 4 off-site payloads (http://evil.com, //evil.com,
	// https://evil.com, javascript:alert(1)). The same-host "/%09/evil.com"
	// echo must NOT be flagged now that the Location is parsed and resolved
	// against the origin host instead of substring-matched.
	if len(result) != 20 {
		t.Fatalf("Expected 20 vulnerable results, got %d", len(result))
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("Expected status vulnerable, got %q (%s)", r.Status, r.Detail)
		}
	}
}

// TestOpenRedirectIsOffSite_BrowserNormalization pins the browser-style
// Location normalizations: backslash-as-slash, single-slash scheme forms,
// control-byte stripping, and default-port-insensitive host comparison.
func TestOpenRedirectIsOffSite_BrowserNormalization(t *testing.T) {
	base, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatalf("failed to parse base URL: %v", err)
	}
	cases := []struct {
		loc  string
		want bool
	}{
		{`\\evil.com`, true},               // browser resolves \\ to protocol-relative //
		{`/\evil.com`, true},               // partial backslash form
		{"http:/evil.com", true},           // single-slash authority form
		{"\nhttp://evil.com", true},        // embedded control bytes are ignored
		{"http://evil.com:80", true},       // default port stripped before compare
		{"http://evil.com:8443", true},     // non-default port still off-site
		{"http://EVIL.com", true},          // host comparison is case-insensitive
		{"//evil.com", true},               // protocol-relative
		{"/local/path", false},             // stays on-host
		{"http://example.com:80/x", false}, // own host on default port
		{"http://example.com", false},
		{"https://example.com:443", false},   // own host on default https port
		{"/error?to=http://evil.com", false}, // payload merely echoed in query
	}
	for _, tc := range cases {
		if got := openRedirectIsOffSite(base, tc.loc); got != tc.want {
			t.Errorf("openRedirectIsOffSite(%q) = %v, want %v", tc.loc, got, tc.want)
		}
	}
}

// TestOpenRedirect_Execute_BackslashLocationFlagged pins the end-to-end path:
// a server emitting a backslash Location must be flagged as vulnerable even
// though Go's URL parser would keep it on-host.
func TestOpenRedirect_Execute_BackslashLocationFlagged(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", `\\evil.com`)
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOpenRedirect("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatalf("expected vulnerable findings for a \\evil.com redirect, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("expected status vulnerable, got %q (%s)", r.Status, r.Detail)
		}
	}
}

// TestOpenRedirect_Execute_DefaultPortLocationFlagged pins the host
// comparison: http://evil.com:80 must be treated as off-site despite the
// default port.
func TestOpenRedirect_Execute_DefaultPortLocationFlagged(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "http://evil.com:80")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOpenRedirect("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatalf("expected vulnerable findings for an evil.com:80 redirect, got none")
	}
	for _, r := range result {
		if r.Status != "vulnerable" {
			t.Fatalf("expected status vulnerable, got %q (%s)", r.Status, r.Detail)
		}
	}
}

func TestOpenRedirect_Execute_CanceledContext(t *testing.T) {
	module := NewOpenRedirect("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestOpenRedirect_Execute_NoVulnerability(t *testing.T) {
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

	module := NewOpenRedirect("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}
