package core

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SessionFixationTestingResult holds the result of the SessionFixationTesting module execution.
type SessionFixationTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SessionFixationTesting executes the session_fixation_testing security technique.
type SessionFixationTesting struct {
	BaseModule
	Target  string
	results []SessionFixationTestingResult

	probeAttempts int
	probeErrors   int
	lastProbeErr  error
}

// NewSessionFixationTesting creates a new instance.
func NewSessionFixationTesting(target string) *SessionFixationTesting {
	return &SessionFixationTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *SessionFixationTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// sessionFixationPasswordPattern matches quoted and unquoted password inputs
// (type=password, type="password", type='password').
var sessionFixationPasswordPattern = regexp.MustCompile(`(?i)type\s*=\s*["']?password`)

// sessionFixationLoginSuccessSignals are markers that a POST with test/test
// produced an authenticated context. Failed-login pages must not trigger the
// judge. Navigation vocabulary (dashboard / my account / logout) is
// deliberately excluded: site templates render those links on failed-login
// pages too.
var sessionFixationLoginSuccessSignals = []string{"logged in", "logged_in", "loginsuccess", "signon success", "sign-on complete", "welcome back", "authenticated"}

// sessionFixationLoginFailureSignals are markers that the login POST was
// rejected. They veto a success verdict even when nav-ish success words or a
// Set-Cookie are also present.
var sessionFixationLoginFailureSignals = []string{"invalid", "incorrect", "wrong password", "login failed", "authentication failed", "bad credentials", "account locked", "locked", "denied", "failed"}

func (m *SessionFixationTesting) Execute(ctx context.Context) ([]SessionFixationTestingResult, error) {
	m.results = make([]SessionFixationTestingResult, 0)

	// Perform a GET request to see if there's a password field
	getReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	getResp, err := m.Client.Do(getReq)
	if err != nil {
		m.results = append(m.results, SessionFixationTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Could not fetch login page: %v", err)),
		})
		return m.results, nil
	}
	defer getResp.Body.Close()

	getBodyBytes, _ := ReadBoundedBody(getResp.Body, MaxResponseBodyBytes)
	getBodyStr := string(getBodyBytes)

	if !sessionFixationPasswordPattern.MatchString(getBodyStr) {
		// Not a login endpoint, skip blind POST to reduce false positives.
		m.results = append(m.results, SessionFixationTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "No password input found on the page (quoted or unquoted); session fixation testing skipped."),
		})
		return m.results, nil
	}

	// Since we don't have real credentials, we just simulate the flow:
	// 1. Send a request with a fake predetermined session ID
	// 2. See if the server accepts it or forces a new one

	sessionNames := []string{"PHPSESSID", "JSESSIONID", "session_id", "ASP.NET_SessionId"}

	jobs := make(chan string, len(sessionNames))
	for _, s := range sessionNames {
		jobs <- s
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cookieName := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testCookie(ctx, cookieName)
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
		m.Mu.Lock()
		attempts, errors := m.probeAttempts, m.probeErrors
		m.Mu.Unlock()
		if attempts == 0 && errors > 0 {
			m.results = append(m.results, SessionFixationTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All %d login POST probes failed with transport errors; session rotation could not be observed.", errors)),
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

// sessionFixationLoginSucceeded reports whether a login response looks
// authenticated. A failed login that returns 200 with no new cookie must
// never be judged as a fixation finding. A Set-Cookie on the POST response is
// strong evidence of an established session, but a body carrying failure
// markers is a failed login even when success words appear elsewhere.
func sessionFixationLoginSucceeded(statusCode int, body string, setCookies []string) bool {
	bodyLower := strings.ToLower(body)
	failed := containsAnyToken(bodyLower, sessionFixationLoginFailureSignals)

	if statusCode >= 300 {
		// Redirect without a session cookie is typical of a failed login or a
		// re-render; a redirect that grants access will carry Set-Cookie.
		return len(setCookies) > 0 && !failed
	}
	if statusCode < 200 || statusCode >= 300 {
		return false
	}
	if len(setCookies) > 0 {
		return !failed
	}
	return !failed && containsAnyToken(bodyLower, sessionFixationLoginSuccessSignals)
}

// sessionFixationHopCookies extracts the Set-Cookie values from a raw
// (non-followed) response so cookies issued on intermediate 302 hops are visible.
func sessionFixationHopCookies(resp *http.Response) []string {
	return resp.Header.Values("Set-Cookie")
}

func (m *SessionFixationTesting) testCookie(ctx context.Context, cookieName string) {
	fakeSessionID := "1234567890abcdef1234567890abcdef"

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader("username=test&password=test"))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: fakeSessionID})

	// A dedicated client that does not follow redirects: the rotation cookie
	// is issued on the 302 hop, which a redirect-following client never sees
	// in resp.Cookies().
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: m.Client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.lastProbeErr = err
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	m.Mu.Lock()
	m.probeAttempts++
	m.Mu.Unlock()

	body, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)

	// Verify the login actually succeeded before judging rotation behavior.
	if !sessionFixationLoginSucceeded(resp.StatusCode, string(body), sessionFixationHopCookies(resp)) {
		return
	}

	// Gather cookies from every hop: since redirects are not followed, the
	// first (possibly 302) response carries the rotation cookie.
	setCookies := sessionFixationHopCookies(resp)

	// Check if the server issued a new session ID to replace ours
	replaced := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName {
			replaced = true
			if cookie.Value == fakeSessionID {
				// Server echoed our fake session ID back without changing it
				m.Mu.Lock()
				m.RecordPoC(req, nil, "Potential Session Fixation: Server accepted and retained fake session ID for "+cookieName)
				m.results = append(m.results, SessionFixationTestingResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, "Potential Session Fixation: Server accepted and retained fake session ID for "+cookieName),
				})
				m.Mu.Unlock()
			}
		}
	}

	if !replaced && len(setCookies) == 0 {
		// Server didn't issue any cookies and the login succeeded: no client
		// jar is in play, so the only session identifier the server could have
		// bound to the new session is our attacker-chosen fake ID — a directly
		// confirmed session fixation.
		m.Mu.Lock()
		m.results = append(m.results, SessionFixationTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, "Session Fixation: Server did not rotate the pre-authenticated session cookie "+cookieName+" after a successful login; the attacker-chosen session ID remains valid post-authentication."),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("session_fixation_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting SessionFixationTesting on: %s", target))

		tester := NewSessionFixationTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
