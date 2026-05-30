package core

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var sharedCookieJar http.CookieJar

func init() {
	sharedCookieJar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

// NewHTTPClient returns a configured *http.Client with reasonable timeouts, insecure skip verify, and a shared CookieJar.
var DefaultTransport http.RoundTripper = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: DefaultTransport,
		Jar:       sharedCookieJar,
	}
}

// EnsureHTTPPrefix ensures the target URL starts with http:// or https://
func EnsureHTTPPrefix(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
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
	return host
}
