package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PasswordSprayingResult holds the result of the PasswordSpraying module execution.
type PasswordSprayingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PasswordSpraying executes the password_spraying security technique.
type PasswordSpraying struct {
	BaseModule
	Target          string
	results         []PasswordSprayingResult
	lockoutDetected bool
	aborted         bool
}

// NewPasswordSpraying creates a new instance.
func NewPasswordSpraying(target string) *PasswordSpraying {
	client := NewHTTPClient(10 * time.Second)
	// Do not follow redirects: login flows signal success/failure via 302
	// Location, and following them would hide the redirect target.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &PasswordSpraying{
		BaseModule: BaseModule{
			Client:     client,
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *PasswordSpraying) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var sprayUsernames = []string{
	"admin", "root", "user", "test", "administrator", "guest", "info", "webmaster", "sysadmin", "support",
}

const sprayPassword = "Password1!"

// spraySuccessMarkers are positive-login markers; the baseline probe uses
// invalid credentials, so a baseline response carrying one of them indicates
// the endpoint accepts anything and spraying findings are meaningless.
var spraySuccessMarkers = []string{"welcome", "dashboard", "logged in", "sign-on complete", "authenticated", "session established"}

// sprayLockoutLocationTokens are whole path tokens (the Location split on
// non-alphanumerics) that identify a lockout/throttling redirect. Substring
// matching would also fire on benign paths such as /blocked or /moderate.
var sprayLockoutLocationTokens = map[string]bool{
	"lock": true, "locked": true, "locking": true, "unlock": true,
	"rate": true, "throttle": true, "throttled": true, "throttling": true,
	"attempt": true, "attempts": true,
}

// sprayLocationIndicatesLockout reports whether any path token of a redirect
// Location is an exact lockout/throttling marker.
func sprayLocationIndicatesLockout(location string) bool {
	for _, tok := range strings.FieldsFunc(strings.ToLower(location), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if sprayLockoutLocationTokens[tok] {
			return true
		}
	}
	return false
}

// sprayBaseline holds the outcome of the invalid-credential baseline request.
type sprayBaseline struct {
	authBypass  bool   // baseline failure response itself looked like a successful login
	location    string // baseline redirect target, if any
	cookieNames map[string]bool
	body        string
	statusCode  int
}

func (m *PasswordSpraying) getBaselineAuthBypass(ctx context.Context) (sprayBaseline, error) {
	baseline := sprayBaseline{cookieNames: map[string]bool{}}
	body := "username=invalid_user_12345&password=invalid_password_12345"
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader(body))
	if err != nil {
		return baseline, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return baseline, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return baseline, err
	}

	baseline.statusCode = resp.StatusCode
	baseline.body = string(bodyBytes)
	baseline.location = resp.Header.Get("Location")
	for _, c := range resp.Cookies() {
		baseline.cookieNames[c.Name] = true
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		locationLower := strings.ToLower(baseline.location)

		isLikelyError := false
		if baseline.location != "" && (strings.Contains(locationLower, "error") || strings.Contains(locationLower, "login") || strings.Contains(locationLower, "retry")) {
			isLikelyError = true
		}

		bodyStr := strings.ToLower(baseline.body)

		if resp.StatusCode == http.StatusOK && (strings.Contains(bodyStr, "invalid") || strings.Contains(bodyStr, "incorrect") || strings.Contains(bodyStr, "wrong") || strings.Contains(bodyStr, "failed")) {
			isLikelyError = true
		}

		// The baseline failure response itself carries a success marker only
		// when it positively looks like a logged-in page (2xx) or redirects to
		// a non-auth target (3xx) — never merely because it sets a cookie or
		// redirects anywhere.
		successMarker := false
		if resp.StatusCode == http.StatusOK && containsAnyToken(bodyStr, spraySuccessMarkers) {
			successMarker = true
		}
		if (resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther) && baseline.location != "" && !isLikelyError {
			successMarker = true
		}

		if successMarker && !isLikelyError {
			baseline.authBypass = true
		}
	}
	return baseline, nil
}

func (m *PasswordSpraying) Execute(ctx context.Context) ([]PasswordSprayingResult, error) {
	m.results = make([]PasswordSprayingResult, 0)
	m.lockoutDetected = false
	m.aborted = false

	baseline, err := m.getBaselineAuthBypass(ctx)
	if err != nil {
		m.results = append(m.results, PasswordSprayingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline authentication probe failed: " + err.Error(),
		})
		return m.results, nil
	}

	// A 429 on the baseline probe means rate limiting is already active:
	// spraying further would only deepen lockouts.
	if baseline.statusCode == http.StatusTooManyRequests {
		m.Mu.Lock()
		m.lockoutDetected = true
		m.Mu.Unlock()
		m.appendLockoutInconclusive()
		return m.results, nil
	}

	jobs := make(chan string, len(sprayUsernames))
	for _, u := range sprayUsernames {
		jobs <- u
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for username := range jobs {
				m.Mu.Lock()
				aborted := m.aborted
				m.Mu.Unlock()
				if aborted {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					m.testUsername(ctx, username, baseline)
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		<-done
		m.appendLockoutInconclusive()
		return m.results, ctx.Err()
	}

	m.appendLockoutInconclusive()
	return m.results, nil
}

func (m *PasswordSpraying) appendLockoutInconclusive() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if m.lockoutDetected {
		m.results = append(m.results, PasswordSprayingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Account lockout or rate limiting detected during spraying; remaining usernames skipped.",
		})
	}
}

// sameRedirectPath reports whether two Location values refer to the same
// redirect target, comparing parsed, slash-normalized paths so "/login" vs
// "/login/" and absolute-vs-relative forms of the same path compare equal.
func sameRedirectPath(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	pa, errA := url.Parse(strings.TrimSpace(a))
	pb, errB := url.Parse(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return false
	}
	return "/"+strings.Trim(pa.Path, "/") == "/"+strings.Trim(pb.Path, "/")
}

func (m *PasswordSpraying) testUsername(ctx context.Context, username string, baseline sprayBaseline) {
	body := "username=" + username + "&password=" + sprayPassword
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// HTTP 429 anywhere is an active rate limiter: treat it as a lockout and
	// abort the remaining spray jobs.
	if resp.StatusCode == http.StatusTooManyRequests {
		m.Mu.Lock()
		m.lockoutDetected = true
		m.aborted = true
		m.Mu.Unlock()
		return
	}

	// 200 OK or 302 Redirect might indicate a successful login
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		locationLower := strings.ToLower(location)

		isLikelyError := false
		if location != "" && (strings.Contains(locationLower, "error") || strings.Contains(locationLower, "login") || strings.Contains(locationLower, "retry")) {
			isLikelyError = true
		}

		bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
		if err != nil {
			return
		}
		bodyStr := strings.ToLower(string(bodyBytes))

		// Lockout / rate-limit pages must never be judged as successful logins;
		// abort the remaining spray jobs once detected. The bare word "attempt"
		// also appears on ordinary failure pages, so it only counts as a lockout
		// signal alongside the stronger lockout/throttling markers.
		isLockout := strings.Contains(bodyStr, "locked") ||
			strings.Contains(bodyStr, "throttl") ||
			strings.Contains(bodyStr, "too many")
		if !isLockout && strings.Contains(bodyStr, "attempt") &&
			(strings.Contains(bodyStr, "too many") || strings.Contains(bodyStr, "maximum") ||
				strings.Contains(bodyStr, "locked") || strings.Contains(bodyStr, "throttl")) {
			isLockout = true
		}
		if isLockout {
			m.Mu.Lock()
			m.lockoutDetected = true
			m.aborted = true
			m.Mu.Unlock()
			return
		}

		// A 3xx redirect to a lockout/throttling target is a lockout signal too.
		if resp.StatusCode != http.StatusOK && sprayLocationIndicatesLockout(location) {
			m.Mu.Lock()
			m.lockoutDetected = true
			m.aborted = true
			m.Mu.Unlock()
			return
		}

		// A redirect counts as a successful login only when it goes somewhere
		// other than the baseline's (failed-login) redirect target. Paths are
		// compared normalized so "/login" vs "/login/" and absolute-vs-relative
		// forms of the same path compare equal.
		if location != "" && sameRedirectPath(location, baseline.location) {
			isLikelyError = true
		}

		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			// Success via redirect requires a Location that is not the failed
			// login target and carries no error markers.
			if location != "" && !isLikelyError {
				if !baseline.authBypass {
					m.Mu.Lock()
					m.RecordPoC(req, nil, "Successful login found via spraying: "+username+" / "+sprayPassword)
					m.results = append(m.results, PasswordSprayingResult{
						Target: m.Target,
						Status: "vulnerable",
						Detail: "Successful login found via spraying: " + username + " / " + sprayPassword,
					})
					m.Mu.Unlock()
				}
			}
			return
		}

		// 200 OK: failure-marker pages can never be successful logins.
		if strings.Contains(bodyStr, "invalid") || strings.Contains(bodyStr, "incorrect") || strings.Contains(bodyStr, "wrong") || strings.Contains(bodyStr, "failed") {
			return
		}

		// Success oracle: the response must set at least one cookie name the
		// baseline response did not set AND its normalized body must differ
		// from the baseline body. Length differences and any-cookie heuristics
		// are not evidence of a session.
		newCookie := false
		for _, c := range resp.Cookies() {
			if !baseline.cookieNames[c.Name] {
				newCookie = true
				break
			}
		}
		if !newCookie || normalizedCompactLower(string(bodyBytes)) == normalizedCompactLower(baseline.body) {
			return
		}

		if !baseline.authBypass {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "Successful login found via spraying: "+username+" / "+sprayPassword)
			m.results = append(m.results, PasswordSprayingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Successful login found via spraying: " + username + " / " + sprayPassword,
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("password_spraying", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting PasswordSpraying on: %s", target))

		tester := NewPasswordSpraying(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
