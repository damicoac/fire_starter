package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOAuthMisconfiguration_Execute(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "https://evil.com/callback")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected results, got none")
	}
	foundVulnerable := false
	for _, r := range result {
		if r.Status == "vulnerable" {
			foundVulnerable = true
			break
		}
	}
	if !foundVulnerable {
		t.Fatalf("expected at least one vulnerable result, got %#v", result)
	}
}

func TestOAuthMisconfiguration_Execute_CanceledContext(t *testing.T) {
	module := NewOAuthMisconfiguration("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}

func TestOAuthMisconfiguration_Execute_NoVulnerability(t *testing.T) {
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

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}

func TestOAuthMisconfiguration_Execute_InconclusiveWhenAllProbesFail(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return nil // simulate transport failure
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) == 0 {
		t.Fatalf("expected an inconclusive result when all probes fail, got none")
	}
	for _, r := range res {
		if r.Status != "inconclusive" {
			t.Fatalf("expected inconclusive result on transport failure, got %#v", r)
		}
	}
}

func TestOAuthMisconfiguration_Execute_LoginRedirectNotCSRFExposure(t *testing.T) {
	// A stateless authorize request that redirects into the login flow is
	// expected unauthenticated behavior: the row must stay inconclusive and
	// the detail must not assert CSRF exposure.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "/login?next=%2Fauthorize")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundInconclusive := false
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("login redirect must not be reported as a state-less CSRF exposure: %s", r.Detail)
		}
		if r.Status == "inconclusive" {
			foundInconclusive = true
			if strings.Contains(strings.ToLower(r.Detail), "csrf") {
				t.Fatalf("login redirect detail must not assert CSRF exposure: %s", r.Detail)
			}
		}
	}
	if !foundInconclusive {
		t.Fatalf("expected at least one inconclusive row for login redirects, got %#v", res)
	}
}

func TestOAuthMisconfiguration_Execute_NoFalsePositiveOnSuffixHost(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "https://notevil.com/callback")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("notevil.com must not be flagged as evil.com redirect, got %#v", r)
		}
	}
}

func TestOAuthMisconfiguration_Execute_NoFalsePositiveOnReflectedErrorPage(t *testing.T) {
	// The evil URL is reflected inside an error message and there is unrelated
	// JS containing window.location — neither is a redirect construct that
	// actually sends the victim to evil.com.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(
					`<html><body><p>Invalid redirect_uri: https://evil.com must be registered.</p>` +
						`<script>window.location.href = "/dashboard";</script></body></html>`)),
				Header: make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("reflected error text plus unrelated JS must not be flagged, got %#v", r)
		}
	}
}

func TestOAuthMisconfiguration_Execute_DetectsMetaRefreshClientSideRedirect(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(
					`<html><head><meta http-equiv="refresh" content="0; url=https://evil.com/callback"></head>` +
						`<body></body></html>`)),
				Header: make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	found := false
	for _, r := range res {
		if r.Status == "vulnerable" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("meta-refresh construct containing evil.com should be detected, got %#v", res)
	}
}

func TestOAuthMisconfiguration_Execute_LocationXSSReflectionIsInformational(t *testing.T) {
	// A payload reflected into the Location header is input reflection, not
	// confirmed XSS: it must be reported as informational and must never
	// produce a vulnerable row or a PoC.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			h := make(http.Header)
			h.Set("Location", "/redirect?target=javascript:prompt(1)")
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewBufferString("")),
				Header:     h,
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	foundInformational := false
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("Location-header reflection must not be reported as vulnerable XSS, got %#v", r)
		}
		if r.Status == "informational" && strings.Contains(r.Detail, "Location header") {
			foundInformational = true
		}
	}
	if !foundInformational {
		t.Fatalf("expected an informational input-reflection row for the Location header, got %#v", res)
	}
	if len(module.GetPoCs()) != 0 {
		t.Fatalf("input reflection must not record PoCs, got %#v", module.GetPoCs())
	}
}

func TestOAuthMisconfiguration_Execute_AnchorHrefOnlyIsInconclusive(t *testing.T) {
	// An anchor href pointing at the evil URL is user-initiated navigation,
	// not an automatic redirect construct: inconclusive, never vulnerable.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(
					`<html><body><a href="https://evil.com/callback">visit</a></body></html>`)),
				Header: make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewOAuthMisconfiguration("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	foundInconclusive := false
	for _, r := range res {
		if r.Status == "vulnerable" {
			t.Fatalf("anchor href alone must not be flagged vulnerable, got %#v", r)
		}
		if r.Status == "inconclusive" {
			foundInconclusive = true
		}
	}
	if !foundInconclusive {
		t.Fatalf("expected an inconclusive row for anchor-href reflection, got %#v", res)
	}
}
