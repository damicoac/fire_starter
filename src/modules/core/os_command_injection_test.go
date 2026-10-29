package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOSCommandInjection_Comprehensive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")

		// 1. Reflection Detection (id command)
		if strings.Contains(cmd, "id") {
			// Verification stage for reflection
			if strings.Contains(cmd, "echo VERIFIED") {
				fmt.Fprint(w, "VERIFIED")
				return
			}
			fmt.Fprint(w, "uid=1000(user) gid=1000(user) groups=1000(user)")
			return
		}

		// 2. Time-based Detection (sleep command)
		if strings.Contains(cmd, "sleep 5") {
			time.Sleep(300 * time.Millisecond) // Mock delay
			fmt.Fprint(w, "OK")
			return
		}
		if strings.Contains(cmd, "sleep 0") {
			// Should be fast
			fmt.Fprint(w, "OK")
			return
		}

		// 3. Boolean Detection (echo VULNERABLE)
		if strings.Contains(cmd, "echo VULNERABLE") {
			fmt.Fprint(w, "VULNERABLE")
			return
		}
		if strings.Contains(cmd, "echo VERIFIED") {
			fmt.Fprint(w, "VERIFIED")
			return
		}

		fmt.Fprint(w, "Safe")
	}))
	defer ts.Close()

	ctx := context.Background()
	m := NewOSCommandInjection(ts.URL)
	m.SetThreshold(200 * time.Millisecond) // Set threshold to be triggered by our mock sleep
	m.MaxThreads = 1                       // Sequential for easier debugging if needed

	results, err := m.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	foundReflection := false
	foundTimeBased := false
	foundBoolean := false

	for _, res := range results {
		if strings.Contains(res.Detail, "reflection") {
			foundReflection = true
		}
		if strings.Contains(res.Detail, "time_based") {
			foundTimeBased = true
		}
		if strings.Contains(res.Detail, "boolean") {
			foundBoolean = true
		}
	}

	if !foundReflection {
		t.Errorf("Expected reflection vulnerability to be found")
	}
	if !foundTimeBased {
		t.Errorf("Expected time-based vulnerability to be found")
	}
	if !foundBoolean {
		t.Errorf("Expected boolean vulnerability to be found")
	}
}

func TestOSCommandInjection_FalsePositive_TimeBased(t *testing.T) {
	// Baseline requests are fast, but BOTH "sleep 5" and the "sleep 0"
	// fast-check payload are slow: a plain slow server, not command execution.
	// With a fast baseline the time-based judge triggers on "sleep 5", and the
	// fast-rejection branch (baseline-adjusted threshold) must reject it.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "sleep") {
			time.Sleep(300 * time.Millisecond)
		}
		fmt.Fprint(w, "Slow Server")
	}))
	defer ts.Close()

	ctx := context.Background()
	m := NewOSCommandInjection(ts.URL)
	m.SetThreshold(200 * time.Millisecond)

	results, err := m.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should not find time-based vulnerabilities because sleep 0 will also be slow
	for _, res := range results {
		if strings.Contains(res.Detail, "time_based") {
			t.Errorf("Found false positive time-based vulnerability: %s", res.Detail)
		}
	}
}

// TestOSCommandInjection_EchoPageNoFalsePositive pins the per-vector canary
// fix: a page that reflects any parameter value must not report the reflected
// "echo VULNERABLE" payload as command execution.
func TestOSCommandInjection_EchoPageNoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		fmt.Fprintf(w, "you searched for: %s", cmd) // echoes any input verbatim
	}))
	defer ts.Close()

	ctx := context.Background()
	m := NewOSCommandInjection(ts.URL)
	m.MaxThreads = 1

	results, err := m.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("reflecting page must yield 0 findings, got %d: %+v", len(results), results)
	}
}

func TestOSCommandInjection_Execute_CanceledContext(t *testing.T) {
	module := NewOSCommandInjection("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	results, err := module.Execute(ctx)
	if err == nil {
		// Cancellation before the baseline produces an inconclusive row
		// instead of an error; either way the run must not report findings.
		if len(results) == 0 {
			t.Fatalf("expected context.Canceled or an inconclusive row, got neither: %d results", len(results))
		}
		for _, r := range results {
			if r.Status == "vulnerable" {
				t.Fatalf("canceled run must not report vulnerable findings: %+v", r)
			}
		}
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOSCommandInjection_Execute_InvalidURL(t *testing.T) {
	module := NewOSCommandInjection("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestOSCommandInjection_Execute_HTTPError(t *testing.T) {
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

	module := NewOSCommandInjection("http://example.com")
	ctx := context.Background()
	results, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range results {
		if res.Status == "vulnerable" {
			t.Fatalf("unexpected vulnerable finding on uniform-500 target: %+v", res)
		}
	}
}
