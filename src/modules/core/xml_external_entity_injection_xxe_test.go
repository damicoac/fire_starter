package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestXMLExternalEntityInjectionXxe_Execute(t *testing.T) {
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

	module := NewXMLExternalEntityInjectionXxe("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected no results on a clean target, got %d: %+v", len(result), result)
	}
}

// A marker in the payload response that is absent from the benign baseline
// POST proves file/URL retrieval via XXE.
func TestXMLExternalEntityInjectionXxe_MarkerDetection(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			respBody := `{"status": "ok"}`
			if req.Body != nil {
				body, _ := io.ReadAll(req.Body)
				if strings.Contains(string(body), "file:///etc/passwd") {
					respBody = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXMLExternalEntityInjectionXxe("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 vulnerable result, got %d: %+v", len(result), result)
	}
	if result[0].Status != "vulnerable" {
		t.Fatalf("expected status vulnerable, got %q", result[0].Status)
	}
}

// A marker that already appears in the ordinary (baseline) response must not
// be reported as XXE-retrieved data.
func TestXMLExternalEntityInjectionXxe_MarkerInBaselineNotVulnerable(t *testing.T) {
	mockTransport := &MockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`docs: root:x:0:0:root:/root:/bin/sh is a common passwd excerpt`)),
				Header:     make(http.Header),
			}
		},
	}
	cleanup := SetMockTransport(mockTransport)
	defer cleanup()

	module := NewXMLExternalEntityInjectionXxe("http://example.com")

	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	for _, res := range result {
		if res.Status == "vulnerable" {
			t.Fatalf("expected no vulnerable results when the marker is present in the baseline, got: %s", res.Detail)
		}
	}
}

func TestXMLExternalEntityInjectionXxe__Execute_CanceledContext(t *testing.T) {
	module := NewXMLExternalEntityInjectionXxe("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = module.Execute(ctx)
}

func TestXMLExternalEntityInjectionXxe__Execute_InvalidURL(t *testing.T) {
	module := NewXMLExternalEntityInjectionXxe("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = module.Execute(ctx)
}

func TestXMLExternalEntityInjectionXxe__Execute_HTTPError(t *testing.T) {
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

	module := NewXMLExternalEntityInjectionXxe("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
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

// A blind-XXE OOB payload must use the payload URL exactly as returned by
// GenerateOOBPayload (already "host/id" shaped): the callback fetch fired by a
// vulnerable parser is recorded by the OOB receiver and reported as vulnerable.
func TestXMLExternalEntityInjectionXxe_OOBInteraction(t *testing.T) {
	oob := &OOBManager{}
	if err := oob.StartOOBReceiver("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer oob.StopOOBReceiver()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if m := xxeSystemRef.FindSubmatch(body); m != nil {
			// A malformed OOB URL (e.g. "http://http://...") fails here, so no
			// interaction is recorded and the module cannot report vulnerable.
			// The callback client is a bare transport (no proxy, short timeout)
			// so the dial to the local OOB receiver cannot hang the handler.
			cb := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
			resp, err := cb.Get(string(m[1]))
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	module := NewXMLExternalEntityInjectionXxe(ts.URL)
	module.SetThreads(1)
	module.OOB = oob
	// Release keep-alive connections before ts.Close so the server is not
	// blocked waiting for them.
	defer module.Client.CloseIdleConnections()

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	found := false
	for _, res := range result {
		if res.Status == "vulnerable" && strings.Contains(strings.ToLower(res.Detail), "oob") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 1 vulnerable OOB-based XXE result, got: %+v", result)
	}
}

// xxeSystemRef matches the blind-XXE parameter entity's SYSTEM target (the
// OOB payload form only; the in-band general entities use different shapes).
var xxeSystemRef = regexp.MustCompile(`<!ENTITY % remote SYSTEM "([^"]+)"`)
