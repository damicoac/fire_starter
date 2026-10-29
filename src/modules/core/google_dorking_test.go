package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGoogleDorking_Execute_ResultURLBody(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<div class="result__url">http://example.com/.env</div>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGoogleDorking("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != len(dorks) {
		t.Fatalf("expected one result per dork (%d), got %d", len(dorks), len(result))
	}
	for _, res := range result {
		if res.Status != "vulnerable" {
			t.Errorf("expected vulnerable status for dork results, got %s (%s)", res.Status, res.Detail)
		}
	}
}

// A results page whose snippet text contains "No results." must still be
// classified by the presence of result links, not downgraded to clean.
func TestGoogleDorking_Execute_ResultsWithNoResultsSnippet(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<a class="result__url" href="https://example.com/backup.sql">snippet: No results. (aside)</a>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGoogleDorking("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != len(dorks) {
		t.Fatalf("expected one result per dork (%d), got %d", len(dorks), len(result))
	}
	for _, res := range result {
		if res.Status != "vulnerable" {
			t.Fatalf("expected vulnerable row for results page containing 'No results.' snippet, got: %+v", res)
		}
	}
}

// A 200 page with neither result links nor the no-results marker is an
// unrecognised layout and must yield inconclusive rows, never a clean scan.
func TestGoogleDorking_Execute_UnrecognizedLayoutInconclusive(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body>Completely different markup</body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGoogleDorking("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != len(dorks) {
		t.Fatalf("expected one result per dork (%d), got %d", len(dorks), len(result))
	}
	for _, res := range result {
		if res.Status != "inconclusive" {
			t.Fatalf("expected inconclusive row for unrecognised layout, got: %+v", res)
		}
	}
}

func TestGoogleDorking_Execute_BotChallengePage(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`<html><body><div class="anomaly-modal">Unfortunately, bots use DuckDuckGo too</div></body></html>`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewGoogleDorking("http://example.com")
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected inconclusive rows for bot-challenge page, got none")
	}
	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Errorf("bot-challenge page must not yield vulnerable findings: %+v", res)
		}
		if res.Status != "inconclusive" || !strings.Contains(res.Detail, "bot challenge") {
			t.Errorf("expected inconclusive challenge detail, got %s / %s", res.Status, res.Detail)
		}
	}
}

func TestGoogleDorking__Execute_CanceledContext(t *testing.T) {
	module := NewGoogleDorking("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestGoogleDorking__Execute_InvalidURL(t *testing.T) {
	module := NewGoogleDorking("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestGoogleDorking__Execute_HTTPError(t *testing.T) {
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

	module := NewGoogleDorking("http://example.com")
	ctx := context.Background()
	result, _ := module.Execute(ctx)
	if len(result) != len(dorks) {
		t.Fatalf("expected inconclusive rows for failed dork requests, got %d", len(result))
	}
	for _, res := range result {
		if res.Status != "inconclusive" {
			t.Errorf("expected inconclusive status for non-200 search response, got %s", res.Status)
		}
	}
}
