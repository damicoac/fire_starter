package core

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// NewHTTPClient returns a configured *http.Client with reasonable timeouts, insecure skip verify, and an independent CookieJar.
var DefaultTransport http.RoundTripper = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   25,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
}

// defaultTransportMu guards Get/Set of DefaultTransport so test mock swaps do
// not race with client construction.
var defaultTransportMu sync.RWMutex

// SetDefaultTransport atomically replaces the package default transport and
// returns a function that restores the previous transport.
func SetDefaultTransport(rt http.RoundTripper) (restore func()) {
	defaultTransportMu.Lock()
	previous := DefaultTransport
	DefaultTransport = rt
	defaultTransportMu.Unlock()
	return func() {
		defaultTransportMu.Lock()
		DefaultTransport = previous
		defaultTransportMu.Unlock()
	}
}

// getDefaultTransport reads DefaultTransport under the package lock.
func getDefaultTransport() http.RoundTripper {
	defaultTransportMu.RLock()
	defer defaultTransportMu.RUnlock()
	return DefaultTransport
}

func NewHTTPClient(timeout time.Duration) *http.Client {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &http.Client{
		Timeout:   timeout,
		Transport: getDefaultTransport(),
		Jar:       jar,
	}
}

// EnsureHTTPPrefix ensures the target URL starts with http:// or https://.
// Targets that already carry a scheme separator (including ftp:// or
// uppercase HTTP://) are returned unchanged.
func EnsureHTTPPrefix(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	return "https://" + target
}

func ExtractHostname(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		candidate = EnsureHTTPPrefix(candidate)
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	if strings.Contains(host, ":") {
		// Re-bracket IPv6 literals so downstream payload construction yields
		// a usable host ("[::1]" instead of "::1").
		return "[" + host + "]"
	}
	return host
}

// ExtractTargetHost extracts the hostname from a URL or target string, supporting both domains and IP addresses.
func ExtractTargetHost(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		candidate = EnsureHTTPPrefix(candidate)
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(parsed.Hostname())
}
