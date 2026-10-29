package core

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"testing"
)

func TestCalcEntropy(t *testing.T) {
	cases := []struct {
		input string
		want  float64
	}{
		{"aaaa", 0},
		{"abcd", 2},
		{"abcdefgh", 3},
		{"", 0},
	}
	for _, c := range cases {
		got := calcEntropy(c.input)
		if math.Abs(got-c.want) > 0.0001 {
			t.Errorf("calcEntropy(%q) = %f, want %f", c.input, got, c.want)
		}
	}
}

func TestCalcEntropy_MultiByteRunes(t *testing.T) {
	// Two distinct runes, each appearing once: entropy must be 1 (rune
	// counting), not skewed by byte lengths.
	got := calcEntropy("é")
	if math.Abs(got-0) > 0.0001 {
		t.Errorf("calcEntropy of single rune = %f, want 0", got)
	}
	got = calcEntropy("éééß")
	// 4 runes: é x3, ß x1 → -(0.75*log2(0.75) + 0.25*log2(0.25)) ≈ 0.811
	want := -(0.75*math.Log2(0.75) + 0.25*math.Log2(0.25))
	if math.Abs(got-want) > 0.0001 {
		t.Errorf("calcEntropy(\"éééß\") = %f, want %f", got, want)
	}
}

func cookieTransport(cookies ...string) *MockTransport {
	return &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     http.Header{"Set-Cookie": cookies},
			}
		},
	}
}

func TestTokenEntropyAnalysis_Execute_LowEntropySessionCookie(t *testing.T) {
	cleanup := SetMockTransport(cookieTransport("sessionid=1000000000000000; Path=/"))
	defer cleanup()

	module := NewTokenEntropyAnalysis("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Errorf("expected vulnerable for low-entropy session cookie, got %s", result[0].Status)
	}
	if result[0].Detail == "" || result[0].Detail[:7] != "Cookie " {
		t.Errorf("unexpected detail: %q", result[0].Detail)
	}
}

func TestTokenEntropyAnalysis_Execute_BenignCookiesSecure(t *testing.T) {
	// consent cookie: not session-like; sessionid: high entropy. No finding.
	cleanup := SetMockTransport(cookieTransport(
		"consent=1; Path=/",
		"medium=somevalue; Path=/",
		"sessionid=aB3x9K2mQ7zR5tV8wY1cE4nJ6hL0pG2sD; Path=/",
	))
	defer cleanup()

	module := NewTokenEntropyAnalysis("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 secure summary row, got %d: %+v", len(result), result)
	}
	if result[0].Status != "secure" {
		t.Errorf("expected secure summary for benign cookies, got %s", result[0].Status)
	}
}

func TestTokenEntropyAnalysis_Execute_NoCookiesInconclusive(t *testing.T) {
	cleanup := SetMockTransport(cookieTransport())
	defer cleanup()

	module := NewTokenEntropyAnalysis("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 inconclusive row, got %d: %+v", len(result), result)
	}
	if result[0].Status != "inconclusive" {
		t.Errorf("expected inconclusive when no cookies observed, got %s", result[0].Status)
	}
}

func TestTokenEntropyAnalysis__Execute_CanceledContext(t *testing.T) {
	module := NewTokenEntropyAnalysis("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestTokenEntropyAnalysis__Execute_InvalidURL(t *testing.T) {
	module := NewTokenEntropyAnalysis("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestTokenEntropyAnalysis__Execute_HTTPError(t *testing.T) {
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

	module := NewTokenEntropyAnalysis("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	if len(result) != 1 || result[0].Status != "inconclusive" {
		t.Errorf("expected inconclusive row on error response, got %+v", result)
	}
}
