package modules

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// NewHTTPClient returns a configured *http.Client with reasonable timeouts and insecure skip verify.
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// EnsureHTTPPrefix ensures the target URL starts with http:// or https://
func EnsureHTTPPrefix(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}
