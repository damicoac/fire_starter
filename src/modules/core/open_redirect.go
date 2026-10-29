package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type OpenRedirectResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type OpenRedirect struct {
	BaseModule
	Target  string
	results []OpenRedirectResult
}

func NewOpenRedirect(target string) *OpenRedirect {
	return &OpenRedirect{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *OpenRedirect) Execute(ctx context.Context) ([]OpenRedirectResult, error) {
	m.results = make([]OpenRedirectResult, 0)

	endpoints := []string{
		"/login?next=",
		"/login?returnUrl=",
		"/logout?redirect=",
		"/redirect?url=",
		"/auth?url=",
	}

	payloads := []string{
		"http://evil.com",
		"//evil.com",
		"https://evil.com",
		"/%09/evil.com",
		"javascript:alert(1)",
	}

	// The request base URL is parsed once; each Location is resolved against
	// it to decide whether the redirect actually leaves the origin host.
	base, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	var probeSuccesses, probeFailures int64

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					for _, p := range payloads {
						if err := m.testRedirect(ctx, base, ep, p); err != nil {
							atomic.AddInt64(&probeFailures, 1)
						} else {
							atomic.AddInt64(&probeSuccesses, 1)
						}
					}
				}
			}
		}()
	}

	wg.Wait()

	// A run where every probe failed on transport errors must not look like a
	// clean scan; surface an inconclusive summary instead.
	if len(m.results) == 0 && probeSuccesses == 0 && probeFailures > 0 {
		m.results = append(m.results, OpenRedirectResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("All %d redirect probes failed with transport errors; open-redirect status could not be determined.", probeFailures),
		})
	}

	return m.results, nil
}

func (m *OpenRedirect) testRedirect(ctx context.Context, base *url.URL, endpoint, payload string) error {
	testURL := m.Target + endpoint + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return err
	}

	// Disable automatic redirects
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: getDefaultTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if openRedirectIsOffSite(base, loc) {
			detail := fmt.Sprintf("Open redirect to %s via %s", loc, testURL)
			m.RecordPoC(req, nil, fmt.Sprintf("Open Redirect at: %s", testURL))
			m.Mu.Lock()
			m.results = append(m.results, OpenRedirectResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: detail,
			})
			m.Mu.Unlock()
		}
	}
	return nil
}

// isOffSiteRedirect reports whether the Location header sends the victim off
// the origin host or into a script/data scheme. The Location is normalized
// browser-style, then parsed and resolved against the request base URL
// instead of substring-matching the payload: relative Locations that merely
// echo the payload (for example "/error?to=http://evil.com" or
// "/%09/evil.com") never leave the host and are not open redirects.
func openRedirectIsOffSite(base *url.URL, loc string) bool {
	loc = openRedirectNormalizeLocation(loc)
	if loc == "" {
		return false
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return false
	}
	if ref.Scheme == "javascript" || ref.Scheme == "data" {
		return true
	}
	resolved := base.ResolveReference(ref)
	return resolved.Host != "" &&
		openRedirectCanonicalHost(resolved.Host) != openRedirectCanonicalHost(base.Host)
}

// openRedirectLocationSchemePrefix matches a leading URL scheme ("http:"),
// used to normalize browser-accepted single-slash authority forms.
var openRedirectLocationSchemePrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)

// openRedirectNormalizeLocation applies the URL cleanups browsers perform but
// Go's url.Parse does not, so a Location that a real browser would resolve
// off-site is not misjudged as same-host:
//   - leading/trailing C0-control and space bytes are stripped and embedded
//     control bytes removed (browsers ignore them);
//   - backslashes become slashes (WHATWG treats "\" as "/" for special
//     schemes, so "\\evil.com" and "/\evil.com" leave the origin);
//   - a scheme with a single slash ("http:/evil.com") gains the missing
//     slash, since browsers normalize it to the authority form.
func openRedirectNormalizeLocation(loc string) string {
	loc = strings.TrimFunc(loc, func(r rune) bool { return r <= 0x20 })
	// Remove embedded control bytes anywhere; browsers ignore them mid-URL.
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, loc)

	s = strings.ReplaceAll(s, "\\", "/")

	if m := openRedirectLocationSchemePrefix.FindString(s); m != "" {
		rest := s[len(m):]
		if strings.HasPrefix(rest, "/") && !strings.HasPrefix(rest, "//") {
			s = m + "/" + rest
		}
	}
	return s
}

// openRedirectCanonicalHost normalizes a URL host for comparison: lowercased
// with the default ports (:80/:443) stripped, so "EVIL.com:80" and "evil.com"
// compare equal while non-default ports keep distinguishing hosts.
func openRedirectCanonicalHost(host string) string {
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "80" || p == "443" {
			return strings.Trim(h, "[]")
		}
		return net.JoinHostPort(h, p)
	}
	return strings.Trim(host, "[]")
}

func init() {
	RegisterModule("open_redirect_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting OpenRedirect on: %s", target))
		tester := NewOpenRedirect(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
