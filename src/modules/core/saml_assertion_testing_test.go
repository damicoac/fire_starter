package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSAMLAssertionTesting_Execute(t *testing.T) {
	// Baseline (malformed garbage) is rejected with 400; forged SAML payloads
	// are accepted with 200 and a positive auth signal.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "invalid_baseline_data") {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid SAML response"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Welcome! You are logged in.</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundVulnerable := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			foundVulnerable = true
		}
	}
	if !foundVulnerable {
		t.Fatalf("expected a vulnerable result when forged SAML is accepted, got %#v", result)
	}
}

func TestSAMLAssertionTesting_Execute_InconclusiveWhenBaselineFails(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil // transport failure for everything
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) == 0 || result[0].Status != "inconclusive" {
		t.Fatalf("expected inconclusive result when baseline request fails, got %#v", result)
	}
}

func TestSAMLAssertionTesting_Execute_NoFindingWhenSPRejects(t *testing.T) {
	// Baseline and payloads all rejected with 400 and an error page.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "Invalid SAML response"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("rejecting SP must not be flagged vulnerable, got %#v", r)
		}
	}
}

// A rejection page containing a negation marker must never be judged an
// accepted forged assertion, even when it also carries a positive auth
// signal and the baseline was rejected with 400.
func TestSAMLAssertionTesting_Execute_NegationPageNotAccepted(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "invalid_baseline_data") {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid SAML response"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html>Welcome to the portal. You are not authenticated — session not established.</html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Negation page with an auth signal must not be flagged vulnerable: %+v", r)
		}
	}
}

// A payload response that differs from the baseline with an auth signal, but
// where the baseline was NOT clearly rejected, must downgrade to
// inconclusive rather than confirmed.
func TestSAMLAssertionTesting_Execute_BaselineNotRejectedDowngrades(t *testing.T) {
	// Baseline: 200 page that itself carries an auth signal (so it is NOT
	// clearly rejected). Payload: 302 redirect with an auth signal.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "invalid_baseline_data") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Welcome to the portal</body></html>`)),
					Header:     make(http.Header),
				}
			}
			hdr := make(http.Header)
			hdr.Set("Location", "/dashboard")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>session established via SamlAuth</body></html>`)),
				Header:     hdr,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	// Keep the 302 visible instead of following it, so the probe response is
	// judged with its redirect status.
	module.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Errorf("Baseline not clearly rejected must downgrade the differential: %+v", r)
		}
	}
	foundInconclusive := false
	for _, r := range result {
		if r.Status == "inconclusive" {
			foundInconclusive = true
		}
	}
	if !foundInconclusive {
		t.Errorf("Expected an inconclusive row for the unconfirmed differential, got %+v", result)
	}
}

// When every probe fails at the transport level (baseline succeeded), the
// module must emit one inconclusive summary row instead of silence.
func TestSAMLAssertionTesting_Execute_AllProbesFailed(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "invalid_baseline_data") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Home page</body></html>`)),
					Header:     make(http.Header),
				}
			}
			return nil // transport error for every payload probe
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewSAMLAssertionTesting("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	foundInconclusive := false
	for _, r := range result {
		if r.Status == "inconclusive" && strings.Contains(r.Detail, "All 4 probes failed") {
			foundInconclusive = true
		}
		if r.Status == "vulnerable" {
			t.Errorf("All-failed probe run must not flag vulnerable: %+v", r)
		}
	}
	if !foundInconclusive {
		t.Errorf("Expected one all-failed inconclusive row, got %+v", result)
	}
}

func TestSAMLAssertionTesting__Execute_CanceledContext(t *testing.T) {
	module := NewSAMLAssertionTesting("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestSAMLAssertionTesting__Execute_InvalidURL(t *testing.T) {
	module := NewSAMLAssertionTesting("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestSAMLAssertionTesting__Execute_HTTPError(t *testing.T) {
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

	module := NewSAMLAssertionTesting("http://example.com")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

// TestSAMLBodyShowsRejection_WordMatching pins the word-bounded veto: words
// merely containing a marker must not veto, genuine rejection text must.
func TestSAMLBodyShowsRejection_WordMatching(t *testing.T) {
	if samlBodyShowsRejection("Welcome back, you are authenticated. Terminating terror scenario checks.") {
		t.Error("embedded marker word (terror) must not veto")
	}
	if !samlBodyShowsRejection("You are not authenticated. Please sign in.") {
		t.Error("genuine rejection text must veto")
	}
	if !samlBodyShowsRejection("Invalid SAML assertion") {
		t.Error("invalid marker must veto")
	}
}
