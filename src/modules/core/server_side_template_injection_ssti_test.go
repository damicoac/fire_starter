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
			body: "Result is 49",
			payload: SSTIPayload{
				Type:     SSTIMath,
				Value:    "{{7*7}}",
				Expected: "49",
			},
			want: true,
		},
		{
			name: "Math failure (echoed)",
			body: "Result is {{7*7}}",
			payload: SSTIPayload{
				Type:     SSTIMath,
				Value:    "{{7*7}}",
				Expected: "49",
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
		if strings.Contains(q, "{{7*7}}") {
			_, _ = w.Write([]byte("Result: 49"))
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
		if strings.Contains(res.Detail, "math") && strings.Contains(res.Detail, "49") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find math-based SSTI")
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
	mux.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "http://") {
			start := strings.Index(q, "http://")
			end := start
			for end < len(q) && q[end] != '\'' && q[end] != '"' && q[end] != '\\' && q[end] != ')' && q[end] != '}' && q[end] != ' ' {
				end++
			}
			urlStr := q[start:end]
			fmt.Println("OOB URL hit:", urlStr)
			_, _ = http.Get(urlStr) // simulate SSRF/OOB from template
		}
		_, _ = w.Write([]byte("Processed template"))
	})

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
	_, _ = m.Execute(ctx)
}
