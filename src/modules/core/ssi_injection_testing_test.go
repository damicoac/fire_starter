package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSsiInjectionTesting_Execute(t *testing.T) {
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

	module := NewSsiInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected no results on a clean target, got %d: %+v", len(result), result)
	}
}

// An HTML-escaped echo of the SSI marker is inert: the framework escaped the
// reflection instead of executing the directive, and escaping also transforms
// `testvar`, so the marker alone must not count as server-side execution.
func TestSsiInjectionTesting_EscapedEchoNotVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			respBody := `{"status": "ok"}`
			if req.URL.RawQuery != "" {
				respBody = `&lt;!--#set var=&quot;testvar&quot; value=&quot;ssi_vuln_1337&quot; --&gt;&lt;!--#echo var=&quot;testvar&quot; --&gt;`
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSsiInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results for an escaped (inert) SSI echo, got: %s", res.Detail)
		}
	}
}

// Prose that merely contains "1000" and a doc-style uid/gid line spanning far
// more than the bounded character window must not match the id signature.
func TestSsiInjectionTesting_BenignIDPageNotVulnerable(t *testing.T) {
	benignBody := `user id 1000 documented below. ` +
		`uid=1000(alice) groups=1000(alice),docker,ci,build,deploy,release,ops,monitoring,logging,audit,tracing,backup,restore,archive gid=1000(users)`
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			respBody := `{"status": "ok"}`
			if req.URL.RawQuery != "" {
				respBody = benignBody
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSsiInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results for a benign uid=1000 documentation page, got: %s", res.Detail)
		}
	}
}

// A real `id` command output line in the payload response is SSI execution.
func TestSsiInjectionTesting_IdCommandOutputVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			respBody := `{"status": "ok"}`
			if req.URL.RawQuery != "" && strings.Contains(req.URL.RawQuery, "exec") {
				respBody = `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSsiInjectionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 vulnerable result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("expected status vulnerable, got %q", result[0].Status)
	}
}

func TestSsiInjectionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewSsiInjectionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestSsiInjectionTesting__Execute_InvalidURL(t *testing.T) {
	module := NewSsiInjectionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestSsiInjectionTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewSsiInjectionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 inconclusive result when every probe returns HTTP 500, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("expected inconclusive status on HTTP error path, got %q", result[0].Status)
	}
}
