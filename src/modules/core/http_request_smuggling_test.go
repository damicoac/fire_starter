package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type customTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.roundTrip(req)
}

func TestHTTPRequestSmuggling_Execute_CLTE(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			bodyBytes, _ := io.ReadAll(req.Body)
			bodyStr := string(bodyBytes)
			if bodyStr == "baseline" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
					Header:     make(http.Header),
				}, nil
			}
			if bodyStr == "1\r\nA\r\nX" {
				return nil, errors.New("timeout waiting for chunk")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	original := DefaultTransport
	DefaultTransport = custom
	defer func() { DefaultTransport = original }()

	module := NewHTTPRequestSmuggling("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected results for CL.TE vulnerability, got none")
	}
	if result[0].Status != "vulnerable" || result[0].Detail != "Vulnerable to CL.TE request smuggling (timing based)" {
		t.Errorf("Unexpected result: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_TECL(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			bodyBytes, _ := io.ReadAll(req.Body)
			bodyStr := string(bodyBytes)
			if bodyStr == "baseline" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
					Header:     make(http.Header),
				}, nil
			}
			if bodyStr == "0\r\n\r\nX" {
				return nil, errors.New("timeout waiting for byte")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	original := DefaultTransport
	DefaultTransport = custom
	defer func() { DefaultTransport = original }()

	module := NewHTTPRequestSmuggling("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("Expected results for TE.CL vulnerability, got none")
	}
	if result[0].Status != "vulnerable" || result[0].Detail != "Vulnerable to TE.CL request smuggling (timing based)" {
		t.Errorf("Unexpected result: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_BaselineTimeout(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			bodyBytes, _ := io.ReadAll(req.Body)
			bodyStr := string(bodyBytes)
			if bodyStr == "baseline" {
				return nil, errors.New("timeout on baseline")
			}
			return nil, errors.New("timeout on payload")
		},
	}
	original := DefaultTransport
	DefaultTransport = custom
	defer func() { DefaultTransport = original }()

	module := NewHTTPRequestSmuggling("http://example.com")
	ctx := context.Background()
	result, err := module.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result) > 0 {
		t.Fatalf("Expected NO results due to baseline timeout, got: %+v", result)
	}
}

func TestHTTPRequestSmuggling_Execute_NoVulnerability(t *testing.T) {
	custom := &customTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status": "ok"}`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	original := DefaultTransport
	DefaultTransport = custom
	defer func() { DefaultTransport = original }()

	module := NewHTTPRequestSmuggling("http://example.com")
	ctx := context.Background()
	res, _ := module.Execute(ctx)
	if len(res) > 0 {
		t.Fatalf("Expected no results, got %d", len(res))
	}
}

func TestHTTPRequestSmuggling_Execute_CanceledContext(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}
