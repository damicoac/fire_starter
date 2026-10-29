package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSTIValidator(t *testing.T) {
	validator := &SSTIValidator{}

	tests := []struct {
		name    string
		body    string
		payload SSTIPayload
		oobHits []OOBInteraction
		want    bool
	}{
		{
			name: "Math success",
			body: "Result is 19749136",
			payload: SSTIPayload{
				Type:     SSTIMath,
				Value:    "{{4444*4444}}",
				Expected: "19749136",
			},
			want: true,
		},
		{
			name: "Math failure (echoed)",
			body: "Result is {{4444*4444}}",
			payload: SSTIPayload{
				Type:     SSTIMath,
				Value:    "{{4444*4444}}",
				Expected: "19749136",
			},
			want: false,
		},
		{
			name: "OOB success",
			body: "Processed",
			payload: SSTIPayload{
				Type:  SSTIOOB,
				Value: "{{req('http://OOB')}}",
				OOBID: "test-id",
			},
			oobHits: []OOBInteraction{{ID: "test-id"}},
			want:    true,
		},
		{
			name: "OOB failure",
			body: "Processed",
			payload: SSTIPayload{
				Type:  SSTIOOB,
				Value: "{{req('http://OOB')}}",
				OOBID: "test-id",
			},
			oobHits: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validator.IsVulnerable(tt.body, tt.payload, tt.oobHits); got != tt.want {
				t.Errorf("SSTIValidator.IsVulnerable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSTI_MathReflection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "{{4444*4444}}") {
			_, _ = w.Write([]byte("Result: 19749136"))
			return
		}
		_, _ = w.Write([]byte("Hello"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	m := NewServerSideTemplateInjectionSsti(server.URL + "/vulnerable")
	m.SetThreads(1)

	ctx := context.Background()
	results, err := m.Execute(ctx)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, res := range results {
		if strings.Contains(res.Detail, "math") && strings.Contains(res.Detail, "19749136") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find math-based SSTI")
	}
}

// A page that merely echoes the raw template expression is not SSTI: the
// template was never evaluated server-side.
func TestSSTI_MathEchoNotVulnerable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo: {{4444*4444}}"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	m := NewServerSideTemplateInjectionSsti(server.URL + "/vulnerable")
	m.SetThreads(1)

	results, err := m.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results for echoed (unevaluated) template, got: %s", res.Detail)
		}
	}
}

// A page that already contains the evaluated result (IDs, timestamps, plain
// reflection) must not be flagged without a differential against a
// payload-free baseline of the same vector.
func TestSSTI_MathBaselineNotVulnerable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("record 19749136 created at 12:00"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	m := NewServerSideTemplateInjectionSsti(server.URL + "/vulnerable")
	m.SetThreads(1)

	results, err := m.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results when the page already contains the evaluated result, got: %s", res.Detail)
		}
	}
}

func TestSSTI_OOB(t *testing.T) {
	oob := &OOBManager{}
	err := oob.StartOOBReceiver("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer oob.StopOOBReceiver()

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		// The module probes q/name/template query vectors and path-segment
		// vectors; check every carrier so each OOB payload triggers the
		// callback fetch instead of stalling in the 5s interaction poll.
		carrier := r.URL.Query().Get("q")
		if carrier == "" {
			carrier = r.URL.Query().Get("name")
		}
		if carrier == "" {
			carrier = r.URL.Query().Get("template")
		}
		if carrier == "" {
			carrier = r.URL.Path
		}
		// ServeMux path-cleaning collapses "//" to "/" inside path-carried
		// payloads, so match "http:/" and rebuild the scheme explicitly.
		if idx := strings.Index(carrier, "http:/"); idx >= 0 {
			rest := carrier[idx+len("http:/"):]
			rest = strings.TrimPrefix(rest, "/")
			end := 0
			for end < len(rest) && rest[end] != '\'' && rest[end] != '"' && rest[end] != '\\' && rest[end] != ')' && rest[end] != '}' && rest[end] != ' ' {
				end++
			}
			urlStr := "http://" + rest[:end]
			fmt.Println("OOB URL hit:", urlStr)
			_, _ = http.Get(urlStr) // simulate SSRF/OOB from template
		}
		_, _ = w.Write([]byte("Processed template"))
	}
	// Catch-all: path-segment vector probes mutate the URL path, so the
	// handler must match every request shape.
	mux.HandleFunc("/", handler)

	server := httptest.NewServer(mux)
	defer server.Close()

	m := NewServerSideTemplateInjectionSsti(server.URL + "/vulnerable")
	m.SetThreads(1)
	m.OOB = oob

	ctx := context.Background()
	results, err := m.Execute(ctx)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, res := range results {
		if strings.Contains(strings.ToLower(res.Detail), "oob") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find OOB-based SSTI")
	}
}

func TestSSTIValidator_Execute_CanceledContext(t *testing.T) {
	m := NewServerSideTemplateInjectionSsti("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = m.Execute(ctx)
}

func TestSSTIValidator_Execute_InvalidURL(t *testing.T) {
	m := NewServerSideTemplateInjectionSsti("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = m.Execute(ctx)
}

func TestSSTIValidator_Execute_HTTPError(t *testing.T) {
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

	m := NewServerSideTemplateInjectionSsti("http://example.com")
	ctx := context.Background()
	result, err := m.Execute(ctx)
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
