package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type OAuthMisconfigurationResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type OAuthMisconfiguration struct {
	BaseModule
	Target  string
	results []OAuthMisconfigurationResult

	probeSuccesses int
	probeFailures  int
	lastProbeErr   error
}

func NewOAuthMisconfiguration(target string) *OAuthMisconfiguration {
	return &OAuthMisconfiguration{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *OAuthMisconfiguration) Execute(ctx context.Context) ([]OAuthMisconfigurationResult, error) {
	m.results = make([]OAuthMisconfigurationResult, 0)

	endpoints := []string{
		"/oauth/authorize",
		"/oauth2/authorize",
		"/auth/authorize",
		"/login/oauth/authorize",
		"/api/oauth/authorize",
		"/api/oauth2/authorize",
		"/oauth2/v1/authorize",
		"/v1/oauth2/authorize",
	}

	type payloadDef struct {
		qs    string
		isXSS bool
		match string
	}

	payloads := []payloadDef{
		{"?response_type=token&client_id=test&redirect_uri=https://evil.com", false, "evil.com"},
		{"?response_type=code&client_id=test&redirect_uri=https://evil.com", false, "evil.com"},
		{"?response_type=code&client_id=test&redirect_uri=//evil.com", false, "evil.com"},
		{"?response_type=code&client_id=test&redirect_uri=\\\\evil.com", false, "evil.com"},
		{"?response_type=code&client_id=test&redirect_uri=/%09/evil.com", false, "evil.com"},
		{"?response_type=code&client_id=test&redirect_uri=javascript:prompt(1)", true, "javascript:prompt(1)"},
		{"?response_type=code&client_id=test&redirect_uri=\"><script>alert(1)</script>", true, "\"><script>alert(1)</script>"},
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					for _, p := range payloads {
						m.testOAuth(ctx, ep, p.qs, p.isXSS, p.match)
					}
					m.testOAuthState(ctx, ep)
				}
			}
		}()
	}

	wg.Wait()

	m.Mu.Lock()
	successes, failures, lastErr := m.probeSuccesses, m.probeFailures, m.lastProbeErr
	m.Mu.Unlock()
	if successes == 0 && failures > 0 {
		m.results = append(m.results, OAuthMisconfigurationResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All %d OAuth probes failed with transport errors; no authorization endpoint could be tested. Last error: %v", failures, lastErr)),
		})
	}
	return m.results, nil
}

// oauthHostMatchesTarget reports whether host equals or is a subdomain of match.
// Substring matching (strings.Contains) would wrongly flag notevil.com or
// evil.companion.org as the malicious host.
func oauthHostMatchesTarget(host string, match string) bool {
	host = strings.ToLower(strings.Trim(host, "."))
	match = strings.ToLower(strings.Trim(match, "."))
	return host == match || strings.HasSuffix(host, "."+match)
}

// oauthRedirectConstructContainsURL checks whether the evil URL is inside an actual
// redirect construct on the page (meta refresh, JS location assignment, or a
// link href) — not merely reflected in an error message.
func oauthRedirectConstructContainsURL(body string, rawURL string) bool {
	if rawURL == "" {
		return false
	}
	needle := strings.ToLower(rawURL)

	// meta refresh: <meta http-equiv="refresh" content="0; url=...evil.com...">
	metaRe := regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
	for _, tag := range metaRe.FindAllString(body, -1) {
		if strings.Contains(strings.ToLower(tag), needle) {
			return true
		}
	}

	// JS location assignment: window.location / location.href / location.replace
	jsRe := regexp.MustCompile(`(?is)(window\.location(?:\.href)?|location\.href|location\.replace)\s*[(=]?\s*["']([^"']*)["']`)
	for _, m := range jsRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(strings.ToLower(m[2]), needle) {
			return true
		}
	}

	// Anchor href pointing at the evil URL.
	hrefRe := regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']*)["']`)
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(strings.ToLower(m[1]), needle) {
			return true
		}
	}

	// Query-string redirect targets: ?url=... / ?redirect=... / ?next=...
	// Only count when the evil URL appears as (part of) the parameter value.
	qsRe := regexp.MustCompile(`(?is)[?&](url|redirect|redirect_uri|next|continue|return|returnurl|target|dest|destination)=([^&"'\s<]*)`)
	for _, m := range qsRe.FindAllStringSubmatch(body, -1) {
		value := m[2]
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}

	return false
}

func (m *OAuthMisconfiguration) testOAuth(ctx context.Context, endpoint, payload string, isXSS bool, match string) {
	testURL := m.Target + endpoint + payload

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		m.recordProbeFailure(err)
		return
	}

	// We don't want to follow redirects automatically if we want to catch the Location header
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: getDefaultTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		m.recordProbeFailure(err)
		return
	}
	defer resp.Body.Close()
	m.recordProbeSuccess()

	loc := resp.Header.Get("Location")

	if !isXSS {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			isVulnerable := false

			// Parse the location to check the actual host it redirects to.
			if parsedLoc, err := url.Parse(loc); err == nil && parsedLoc.Hostname() != "" {
				if oauthHostMatchesTarget(parsedLoc.Hostname(), match) {
					isVulnerable = true
				}
			} else {
				// Fallback for cases where url.Parse fails or doesn't extract hostname correctly
				locLower := strings.ToLower(loc)
				if strings.HasPrefix(locLower, "http://"+match) ||
					strings.HasPrefix(locLower, "https://"+match) ||
					strings.HasPrefix(locLower, "//"+match) ||
					strings.HasPrefix(locLower, "\\\\"+match) ||
					strings.HasPrefix(locLower, "/\\"+match) {
					isVulnerable = true
				}
			}

			if isVulnerable {
				m.Mu.Lock()
				m.RecordPoC(req, nil, fmt.Sprintf("OAuth redirect_uri manipulation successful at: %s", testURL))
				m.results = append(m.results, OAuthMisconfigurationResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, fmt.Sprintf("OAuth redirect_uri manipulation allowed to %s", loc)),
				})
				m.Mu.Unlock()
			}
		} else if resp.StatusCode == http.StatusOK {
			// Check for potential client-side redirects (e.g. meta refresh or
			// window.location). The evil URL must sit inside the redirect
			// construct itself — a bare reflection in an error message does
			// not redirect anyone.
			body, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
			bodyStr := string(body)
			if oauthRedirectConstructContainsURL(bodyStr, "http://"+match) || oauthRedirectConstructContainsURL(bodyStr, "https://"+match) {
				m.Mu.Lock()
				m.RecordPoC(req, nil, fmt.Sprintf("OAuth redirect_uri reflected in body for client-side redirect at: %s", testURL))
				m.results = append(m.results, OAuthMisconfigurationResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, fmt.Sprintf("OAuth redirect_uri reflected, potential client-side redirect at %s", testURL)),
				})
				m.Mu.Unlock()
			}
		}
	} else {
		// XSS Check
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if strings.HasPrefix(strings.ToLower(loc), match) || strings.Contains(loc, match) {
				m.Mu.Lock()
				m.RecordPoC(req, nil, fmt.Sprintf("OAuth XSS via Location header at: %s", testURL))
				m.results = append(m.results, OAuthMisconfigurationResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, fmt.Sprintf("OAuth redirect_uri reflected in Location header causing XSS at %s", testURL)),
				})
				m.Mu.Unlock()
			}
		} else if resp.StatusCode == http.StatusOK {
			body, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
			if oauthRedirectConstructContainsURL(string(body), match) {
				m.Mu.Lock()
				m.RecordPoC(req, nil, fmt.Sprintf("OAuth redirect_uri XSS reflected in body at: %s", testURL))
				m.results = append(m.results, OAuthMisconfigurationResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, fmt.Sprintf("OAuth redirect_uri reflected causing potential XSS at %s", testURL)),
				})
				m.Mu.Unlock()
			}
		}
	}
}

// oauthRedirectCarriesError reports whether a redirect back to the client carries
// an OAuth error parameter (e.g. error=invalid_request), i.e. the stateless
// request was rejected.
func oauthRedirectCarriesError(loc string) bool {
	parsed, err := url.Parse(loc)
	if err != nil {
		return false
	}
	q := parsed.Query()
	return q.Get("error") != "" || q.Get("error_description") != ""
}

// oauthLooksLikeConsentPage detects an OAuth consent/authorization page shape so a
// plain 200 landing page is not mistaken for the flow proceeding.
func oauthLooksLikeConsentPage(body string) bool {
	if body == "" {
		return false
	}
	return containsAnyToken(body, []string{"consent", "authorize", "authorization", "grant access", "sign in to continue", "allow access"})
}

// oauthRedirectToLoginFlow reports whether a redirect Location sends the user
// into the login/register/authentication flow. A stateless authorize request
// bouncing to the login page is expected unauthenticated behavior, not
// evidence that the flow proceeded without state.
func oauthRedirectToLoginFlow(loc string) bool {
	return containsAnyToken(strings.ToLower(loc), []string{"login", "signin", "sign-in", "auth", "register"})
}

// oauthLoginPageBody reports whether a 2xx body is an authentication page
// (password login/register form) rather than an OAuth consent screen. A login
// page can carry consent-shaped phrases ("sign in to continue") without the
// stateless authorize request having proceeded.
func oauthLoginPageBody(bodyLower string) bool {
	return containsAnyToken(bodyLower, []string{
		`type="password"`, `type='password'`, `type=password`,
		`name="password"`, `name='password'`, `name=password`,
		"create account", "sign up", "forgot your password",
	})
}

func (m *OAuthMisconfiguration) recordProbeFailure(err error) {
	m.Mu.Lock()
	m.probeFailures++
	m.lastProbeErr = err
	m.Mu.Unlock()
}

func (m *OAuthMisconfiguration) recordProbeSuccess() {
	m.Mu.Lock()
	m.probeSuccesses++
	m.Mu.Unlock()
}

// testOAuthState probes whether the authorization endpoint proceeds without a
// state parameter. A valid OAuth client must reject the request (usually 400)
// or redirect back with an error; proceeding to a redirect/consent page
// without state indicates a CSRF-vulnerable authorization flow.
func (m *OAuthMisconfiguration) testOAuthState(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint + "?response_type=code&client_id=test&redirect_uri=https://example.com/callback"

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		m.recordProbeFailure(err)
		return
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: getDefaultTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		m.recordProbeFailure(err)
		return
	}
	defer resp.Body.Close()
	m.recordProbeSuccess()

	body, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	bodyStr := strings.ToLower(string(body))
	loc := resp.Header.Get("Location")

	switch {
	case resp.StatusCode == http.StatusBadRequest:
		// Server rejects the stateless request: correct behavior.
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" && !oauthRedirectCarriesError(loc):
		if oauthRedirectToLoginFlow(loc) {
			// Redirect into the login/register/auth flow is expected
			// unauthenticated behavior, not a state-less authorize flow: keep
			// the row inconclusive without asserting CSRF exposure.
			m.Mu.Lock()
			m.results = append(m.results, OAuthMisconfigurationResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Authorize endpoint redirected to an authentication page (%s); state enforcement could not be assessed from this redirect.", loc)),
			})
			m.Mu.Unlock()
			return
		}
		// Proceeding to a redirect without state: the authorize flow accepted
		// the request with no CSRF protection parameter.
		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("OAuth authorize endpoint proceeded without state parameter at: %s", testURL))
		m.results = append(m.results, OAuthMisconfigurationResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, fmt.Sprintf("Authorize endpoint proceeded without a state parameter (redirected to %s), leaving the flow open to CSRF.", loc)),
		})
		m.Mu.Unlock()
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && oauthLooksLikeConsentPage(bodyStr):
		if oauthLoginPageBody(bodyStr) {
			// The 2xx body is a login/register page with consent-shaped
			// wording, not a proceeding authorize flow: stay inconclusive.
			m.Mu.Lock()
			m.results = append(m.results, OAuthMisconfigurationResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, "Authorize endpoint returned an authentication page; state enforcement could not be assessed from this response."),
			})
			m.Mu.Unlock()
			return
		}
		// A 2xx consent/authorization page without state means the flow
		// proceeded without CSRF protection.
		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("OAuth authorize endpoint proceeded without state parameter at: %s", testURL))
		m.results = append(m.results, OAuthMisconfigurationResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "Authorize endpoint proceeded without a state parameter, leaving the flow open to CSRF."),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("oauth_misconfiguration_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting OAuthMisconfiguration on: %s", target))
		tester := NewOAuthMisconfiguration(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
