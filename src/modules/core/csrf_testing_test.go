package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const csrfTestFormHTML = `<html><body><form method="post" action="/update"><input type="hidden" name="csrf_token" value="abc"><input name="user"></form></body></html>`

func TestCSRFTesting_Execute_TokenAcceptedPath(t *testing.T) {
	// The currently-FP path: a form with a token field where the endpoint
	// accepts POSTs both with and without it. Must NOT report vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"updated"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Token-accepted path must not report vulnerable: %s", res.Detail)
		}
	}
	if len(result) == 0 {
		t.Error("Expected at least one result row for the tested form")
	}
}

func TestCSRFTesting_Execute_TokenRejectedFlow(t *testing.T) {
	// Token enforced: the token-less POST is rejected while the token-bearing
	// POST is accepted. Must NOT report vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "csrf_token=abc") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status":"updated"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":"forbidden"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Token-rejected flow must not report vulnerable: %s", res.Detail)
		}
	}
}

func TestCSRFTesting_Execute_NoForms(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("No-forms target must not report vulnerable: %s", res.Detail)
		}
	}
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Errorf("Expected one inconclusive row for a formless target, got %+v", result)
	}
}

// A genuinely unenforced endpoint must reach vulnerable even though the page
// uses a rotating CSRF token: the token-bearing POST re-renders the page
// (normalized-equal to the baseline) while the token-less POST performs the
// action and returns a different response.
func TestCSRFTesting_Execute_RotatingTokenUnenforcedVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "csrf_token=abc") {
				// Token-bearing POST: the endpoint ignores the (stale,
				// rotated) token and re-renders the form page.
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(csrfTestFormHTML)),
					Header:     make(http.Header),
				}
			}
			// Token-less POST: the action executes.
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"profile updated"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	foundVulnerable := false
	for _, res := range result {
		if res.Status == "vulnerable" {
			foundVulnerable = true
		}
	}
	if !foundVulnerable {
		t.Fatalf("Expected a vulnerable row for the unenforced rotating-token form, got %+v", result)
	}
}

// A token-less POST whose response differs from the baseline only by
// whitespace/case is NOT a state change: with the rotated-token response
// providing the differential, the old byte-exact comparison flagged this as
// vulnerable; the normalized comparison must keep it inconclusive.
func TestCSRFTesting_Execute_WhitespaceOnlyDiffNotVulnerable(t *testing.T) {
	baselineHTML := `<html><body>  <form method="post" action="/update"><input type="hidden" name="csrf_token" value="abc">  <input name="user"></form>  </body></html>`
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "GET" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(baselineHTML)),
					Header:     make(http.Header),
				}
			}
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "csrf_token=abc") {
				// Token-bearing POST: re-rendered page with a rotated token
				// value (normalized-different from the baseline).
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html><body><form method="post" action="/update"><input type="hidden" name="csrf_token" value="rot-999"><input name="user"></form></body></html>`)),
					Header:     make(http.Header),
				}
			}
			// Token-less POST: same page re-rendered with different
			// whitespace and casing only (normalized-equal to the baseline).
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<HTML><BODY><FORM METHOD="POST" ACTION="/UPDATE"><INPUT TYPE="hidden" NAME="csrf_token" VALUE="abc"><INPUT NAME="user"></FORM></BODY></HTML>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewCSRFTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Whitespace-only response difference must not report vulnerable: %s", res.Detail)
		}
	}
	foundInconclusive := false
	for _, res := range result {
		if res.Status == "inconclusive" {
			foundInconclusive = true
		}
	}
	if !foundInconclusive {
		t.Errorf("Expected an inconclusive row for the whitespace-only differential, got %+v", result)
	}
}

func TestCSRFTesting__Execute_CanceledContext(t *testing.T) {
	module := NewCSRFTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestCSRFTesting__Execute_InvalidURL(t *testing.T) {
	module := NewCSRFTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestCSRFTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewCSRFTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("Error-page baseline must not report vulnerable: %s", res.Detail)
		}
	}
}
