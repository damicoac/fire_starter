package core

import (
	"bytes"
	"io"
	"net/http"
)

// MockTransport implements http.RoundTripper and allows us to intercept
// and mock HTTP responses without refactoring the underlying module code.
type MockTransport struct {
	// RoundTripFunc allows injecting custom logic for specific tests.
	RoundTripFunc func(req *http.Request) *http.Response
}

// RoundTrip executes the mock request.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.RoundTripFunc != nil {
		return m.RoundTripFunc(req), nil
	}

	// Default behavior: return 200 OK with empty body.
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Header:     make(http.Header),
	}, nil
}

// SetMockTransport overrides http.DefaultTransport with our MockTransport.
// Returns a cleanup function that restores the original transport.
func SetMockTransport(transport *MockTransport) func() {
	originalTransport := DefaultTransport
	DefaultTransport = transport
	return func() {
		DefaultTransport = originalTransport
	}
}
