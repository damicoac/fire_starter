// src/modules/component_version_analyzer_test.go
package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComponentVersionAnalyzer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Server", "Apache/2.4.41")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.Header().Set("X-AspNet-Version", "4.0.30319")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 5.8" /></head><body><script src="/js/jquery-1.12.4.min.js"></script></body></html>`))
			return
		}
		if r.URL.Path == "/package.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name": "test-app", "version": "1.0.0"}`))
			return
		}
		if r.URL.Path == "/.env" {
			// This one shouldn't match signature because we'll return something else
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`Some random custom error page content`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	analyzer := NewComponentVersionAnalyzer(server.URL)
	results, err := analyzer.Execute(context.Background())

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	foundServer := false
	foundAspNet := false
	foundPackageJson := false
	foundEnvFalsePositive := false

	for _, res := range results {
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "Apache/2.4.41") {
			foundServer = true
		}
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "Found X-AspNet-Version header: 4.0.30319") {
			foundAspNet = true
		}
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "Found exposed configuration file: /package.json") {
			foundPackageJson = true
		}
		if res.Status == "vulnerable" && strings.Contains(res.Detail, "Found exposed configuration file: /.env") {
			foundEnvFalsePositive = true
		}
	}

	if !foundServer {
		t.Errorf("Expected to find Apache server version in headers")
	}
	if !foundAspNet {
		t.Errorf("Expected to find X-AspNet-Version in headers")
	}
	if !foundPackageJson {
		t.Errorf("Expected to find exposed /package.json file")
	}
	if foundEnvFalsePositive {
		t.Errorf("Did not expect to find exposed /.env file because content signature should not match")
	}
}

func TestComponentVersionAnalyzer_Execute_CanceledContext(t *testing.T) {
	analyzer := NewComponentVersionAnalyzer("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _ = analyzer.Execute(ctx)
}

func TestComponentVersionAnalyzer_Execute_InvalidURL(t *testing.T) {
	analyzer := NewComponentVersionAnalyzer("http://invalid-url-:foo")
	ctx := context.Background()
	_, _ = analyzer.Execute(ctx)
}

func TestComponentVersionAnalyzer_Execute_HTTPError(t *testing.T) {
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

	analyzer := NewComponentVersionAnalyzer("http://example.com")
	ctx := context.Background()
	_, _ = analyzer.Execute(ctx)
}
