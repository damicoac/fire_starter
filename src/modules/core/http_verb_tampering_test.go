package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHttpVerbTampering_Execute(t *testing.T) {
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

	module := NewHttpVerbTampering("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got %d", len(result))
	}
	if result[0].Status != "secure" {
		t.Fatalf("Expected secure summary for uniformly-handled verbs, got: %+v", result[0])
	}
}

func TestHttpVerbTampering_Execute_Options200NotFlagged(t *testing.T) {
	// GET baseline 401; OPTIONS/PUT return 200 (normal CORS preflight and
	// unauthenticated PUT mutation must not produce a vulnerability without
	// opt-in); every other verb honors authentication.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "OPTIONS", "PUT":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"ok": true}`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got: %+v", result)
	}
	if result[0].Status != "secure" || result[0].Detail != "All tested verbs were rejected or handled consistently with the GET baseline." {
		t.Fatalf("Unexpected result: %+v", result[0])
	}
	for _, r := range result {
		if strings.Contains(r.Detail, "OPTIONS") {
			t.Fatalf("OPTIONS must not be flagged: %+v", r)
		}
	}
}

func TestHttpVerbTampering_Execute_MutationOptIn_ConfirmedPut(t *testing.T) {
	// With explicit opt-in, a PUT that echoes the probe marker is confirmed.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.Method == "PUT" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"tamper_test":"123"}`)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"resource": "original"}`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	module.SetAllowMutating(true)

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "PUT") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected a confirmed vulnerable PUT finding, got: %+v", result)
	}
}

func TestHttpVerbTampering_Execute_AuthBypassViaTrace(t *testing.T) {
	// GET requires auth but TRACE answers 200 with divergent content in both
	// status and length: the classic verb-tampering auth bypass.
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "TRACE":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html>internal admin panel</html>`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "TRACE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected vulnerable TRACE auth-bypass finding, got: %+v", result)
	}
}

func TestHttpVerbTampering_Execute_BaselineFailure(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	restore := SetDefaultTransport(custom)
	defer restore()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive row on baseline failure, got: %+v", result)
	}
	if result[0].Status != "inconclusive" {
		t.Fatalf("Expected inconclusive on baseline failure, got: %+v", result[0])
	}
}

func TestHttpVerbTampering__Execute_CanceledContext(t *testing.T) {
	module := NewHttpVerbTampering("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestHttpVerbTampering__Execute_InvalidURL(t *testing.T) {
	module := NewHttpVerbTampering("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestHttpVerbTampering__Execute_HTTPError(t *testing.T) {
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

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// Uniform 500 responses: baselines succeed, nothing diverges, no verdicts.
	if len(result) != 1 {
		t.Fatalf("Expected exactly one summary row, got: %+v", result)
	}
	if result[0].Status != "secure" {
		t.Fatalf("Expected secure summary on uniform 500s, got: %+v", result[0])
	}
}

// A server that answers every unknown or mixed-case verb with the same
// catch-all 2xx response is normalizing, not bypassing: the mixed-case rule
// must require divergence from the bogus-verb baseline too.
func TestHttpVerbTampering_Execute_MixedCaseMatchesBogusBaseline(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "GET", "GeT", "POst", "BOGUSVERB", "JEAN_BOGUS_VERB", "OPTIONS", "HEAD", "CONNECT", "TRACE", "TRACK":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`<html>ok</html>`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString(`forbidden`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 || result[0].Status != "secure" {
		t.Fatalf("Expected single secure summary (mixed-case normalized, not a bypass), got: %+v", result)
	}
}

// A mixed-case verb that diverges from BOTH the GET baseline and the
// bogus-verb baseline is a genuine filter bypass (the equal-length bodies
// keep the separate auth-bypass rule out of the way).
func TestHttpVerbTampering_Execute_MixedCaseFilterBypass(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "GET":
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString(`forbidden`)),
					Header:     make(http.Header),
				}
			case "GeT":
				return &http.Response{
					StatusCode: http.StatusOK,
					// Same length as the bogus-verb body so the auth-bypass
					// rule stays silent and the mixed-case rule decides.
					Body:   io.NopCloser(bytes.NewBufferString(`bypasspage`)),
					Header: make(http.Header),
				}
			case "JEAN_BOGUS_VERB":
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`notfound!!`)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString(`forbidden`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "filter bypass") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected mixed-case filter bypass finding, got: %+v", result)
	}
}

// A volatile page must not fake a resource change: with GET samples that
// already disagree with each other, a post-verb GET equal to the second
// sample is not evidence that the verb mutated anything.
func TestHttpVerbTampering_Execute_VolatilePageNotStateChange(t *testing.T) {
	var gets int32
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "PUT":
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
					Header:     make(http.Header),
				}
			case "GET":
				n := atomic.AddInt32(&gets, 1)
				// First GET is short, every later GET is longer: the two
				// baseline samples already disagree, so the page is volatile.
				body := "v1"
				if n > 1 {
					body = "v2-longer"
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString(`forbidden`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	module.SetAllowMutating(true)
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	for _, r := range result {
		if r.Status == "vulnerable" {
			t.Fatalf("Volatile page must not be flagged as state-changing PUT evidence: %+v", result)
		}
	}
	if len(result) != 1 || result[0].Status != "secure" {
		t.Fatalf("Expected single secure summary on volatile page, got: %+v", result)
	}
}

// A genuinely mutated resource still flags: the post-verb GET differs from
// both stable samples and the PUT echoes no probe marker.
func TestHttpVerbTampering_Execute_ResourceChangeConfirmed(t *testing.T) {
	var mutated int32
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			switch req.Method {
			case "PUT":
				atomic.StoreInt32(&mutated, 1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
					Header:     make(http.Header),
				}
			case "GET":
				body := "v1"
				if atomic.LoadInt32(&mutated) == 1 {
					body = "v2-mutated"
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				}
			default:
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString(`forbidden`)),
					Header:     make(http.Header),
				}
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewHttpVerbTampering("http://example.com")
	module.SetAllowMutating(true)
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	found := false
	for _, r := range result {
		if r.Status == "vulnerable" && strings.Contains(r.Detail, "PUT") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Expected confirmed PUT resource-change finding, got: %+v", result)
	}
}
