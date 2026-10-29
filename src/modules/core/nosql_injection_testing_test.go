package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// nosqlMockResponse builds a mock response with the given status and body.
func nosqlMockResponse(status int, body string, extraHeaders map[string]string) *http.Response {
	header := make(http.Header)
	for k, v := range extraHeaders {
		header.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     header,
	}
}

// nosqlRequestBody safely reads a request body (nil for bodyless GETs).
func nosqlRequestBody(req *http.Request) string {
	if req.Body == nil {
		return ""
	}
	bodyBytes, _ := io.ReadAll(req.Body)
	return string(bodyBytes)
}

func TestNosqlInjectionTesting_Execute_MongoErrorLeak_Inconclusive(t *testing.T) {
	// Payload probes surface a MongoDB error signature the baseline does not
	// contain: reported as inconclusive evidence, never as a confirmed vuln.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.Contains(nosqlRequestBody(req), "invalid_user_12345") {
				return nosqlMockResponse(http.StatusUnauthorized, `{"error":"invalid credentials"}`, nil)
			}
			return nosqlMockResponse(http.StatusOK, `{"error":"MongoError: cast to objectid failed"}`, nil)
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected error-leak results, got none")
	}
	for _, res := range results {
		if res.Status == "vulnerable" {
			t.Errorf("Error leak must not be reported as vulnerable: %+v", res)
		}
		if res.Status != "inconclusive" {
			t.Errorf("Expected status inconclusive for error leak, got %q", res.Status)
		}
	}
}

func TestNosqlInjectionTesting_Execute_BypassVersusRejectedBaseline(t *testing.T) {
	// Invalid credentials are rejected with 401; operator probes get a token:
	// the status/body differential confirms the bypass.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.Contains(nosqlRequestBody(req), "invalid_user_12345") {
				return nosqlMockResponse(http.StatusUnauthorized, `{"error":"invalid credentials"}`, nil)
			}
			return nosqlMockResponse(http.StatusOK, `{"token":"abc123"}`, nil)
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	vulnerable := 0
	for _, res := range results {
		if res.Status == "vulnerable" {
			vulnerable++
		}
	}
	if vulnerable == 0 {
		t.Fatalf("Expected at least one vulnerable auth-bypass result, got %+v", results)
	}
}

func TestNosqlInjectionTesting_Execute_TokenBaseline_NoFalsePositive(t *testing.T) {
	// The baseline itself already returns a token for invalid credentials, so a
	// probe response carrying a token is not bypass evidence.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nosqlMockResponse(http.StatusOK, `{"status":"ok","token":"abc123"}`, nil)
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Expected no findings when the baseline already issues tokens, got %+v", results)
	}
}

func TestNosqlInjectionTesting_Execute_BaselineFailure_Inconclusive(t *testing.T) {
	// Unreachable target: the baseline probe fails, so the run must emit one
	// inconclusive row instead of a silently empty (clean-looking) result.
	module := NewNosqlInjectionTesting("http://127.0.0.1:1")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected exactly 1 inconclusive result for a failed baseline, got %+v", results)
	}
	if results[0].Status != "inconclusive" {
		t.Errorf("Expected status inconclusive, got %q", results[0].Status)
	}
	if !strings.Contains(results[0].Detail, "Baseline") {
		t.Errorf("Expected baseline failure detail, got %q", results[0].Detail)
	}
}

func TestNosqlInjectionTesting_Execute_IncidentalCookieNotBypassEvidence(t *testing.T) {
	// A 200 with a non-session cookie (theme=dark) and no token field is not
	// auth-bypass evidence, even against a rejected baseline.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.Contains(nosqlRequestBody(req), "invalid_user_12345") {
				return nosqlMockResponse(http.StatusUnauthorized, `{"error":"invalid credentials"}`, nil)
			}
			return nosqlMockResponse(http.StatusOK, `{"status":"ok"}`, map[string]string{"Set-Cookie": "theme=dark; Path=/"})
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, res := range results {
		if res.Status == "vulnerable" {
			t.Fatalf("incidental cookie must not be bypass evidence: %+v", res)
		}
	}
}

func TestNosqlInjectionTesting_Execute_SessionCookieIsBypassEvidence(t *testing.T) {
	// A 200 with a session-like Set-Cookie against a rejected (401) baseline
	// is bypass evidence: reported vulnerable via the differential.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if strings.Contains(nosqlRequestBody(req), "invalid_user_12345") {
				return nosqlMockResponse(http.StatusUnauthorized, `{"error":"invalid credentials"}`, nil)
			}
			return nosqlMockResponse(http.StatusOK, `{"status":"ok"}`, map[string]string{"Set-Cookie": "session_id=abc123; Path=/; HttpOnly"})
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	results, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	vulnerable := 0
	for _, res := range results {
		if res.Status == "vulnerable" {
			vulnerable++
		}
	}
	if vulnerable == 0 {
		t.Fatalf("Expected a vulnerable auth-bypass finding from a session Set-Cookie, got %+v", results)
	}
}

func TestNosqlInjectionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewNosqlInjectionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestNosqlInjectionTesting__Execute_HTTPError(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nosqlMockResponse(http.StatusInternalServerError, `{"error": "internal server error"}`, nil)
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewNosqlInjectionTesting("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}
