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

func (m *PasswordSpraying) getBaselineAuthBypass(ctx context.Context) (bool, int, string, error) {
	body := "username=invalid_user_12345&password=invalid_password_12345"
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader(body))
	if err != nil {
		return false, 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return false, 0, "", err
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		locationLower := strings.ToLower(location)

		isLikelyError := false
		if location != "" && (strings.Contains(locationLower, "error") || strings.Contains(locationLower, "login") || strings.Contains(locationLower, "retry")) {
			isLikelyError = true
		}

		bodyStr := strings.ToLower(string(bodyBytes))

		if resp.StatusCode == http.StatusOK && (strings.Contains(bodyStr, "invalid") || strings.Contains(bodyStr, "incorrect") || strings.Contains(bodyStr, "wrong") || strings.Contains(bodyStr, "failed")) {
			isLikelyError = true
		}

		if (len(resp.Cookies()) > 0 || location != "") && !isLikelyError {
			return true, len(bodyBytes), location, nil
		}
		return false, len(bodyBytes), location, nil
	}
	return false, len(bodyBytes), "", nil
}

func (m *PasswordSpraying) Execute(ctx context.Context) ([]PasswordSprayingResult, error) {
	m.results = make([]PasswordSprayingResult, 0)
	m.lockoutDetected = false
	m.aborted = false

	baselineAuthBypass, baselineLen, baselineLocation, err := m.getBaselineAuthBypass(ctx)
	if err != nil {
		m.results = append(m.results, PasswordSprayingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline authentication probe failed: " + err.Error(),
		})
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
					m.testUsername(ctx, username, baselineAuthBypass, baselineLen, baselineLocation)
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

func (m *PasswordSpraying) testUsername(ctx context.Context, username string, baselineAuthBypass bool, baselineLen int, baselineLocation string) {
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

		// A redirect counts as a successful login only when it goes somewhere
		// other than the baseline's (failed-login) redirect target. Paths are
		// compared normalized so "/login" vs "/login/" and absolute-vs-relative
		// forms of the same path compare equal.
		if location != "" && sameRedirectPath(location, baselineLocation) {
			isLikelyError = true
		}

		if resp.StatusCode == http.StatusOK {
			if strings.Contains(bodyStr, "invalid") || strings.Contains(bodyStr, "incorrect") || strings.Contains(bodyStr, "wrong") || strings.Contains(bodyStr, "failed") {
				isLikelyError = true
			} else {
				diff := len(bodyBytes) - baselineLen
				if diff < 0 {
					diff = -diff
				}
				isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500
				if !isSignificantlyDifferent {
					isLikelyError = true
				}
			}
		}

		// Just a heuristic - if it doesn't set a cookie or redirect to dashboard, it might be a false positive
		if (len(resp.Cookies()) > 0 || location != "") && !isLikelyError {
			if !baselineAuthBypass {
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
