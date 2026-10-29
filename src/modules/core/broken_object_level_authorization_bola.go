package core

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BrokenObjectLevelAuthorizationBolaResult holds the result of the BrokenObjectLevelAuthorizationBola module execution.
type BrokenObjectLevelAuthorizationBolaResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BrokenObjectLevelAuthorizationBola executes the broken_object_level_authorization_bola security technique.
type BrokenObjectLevelAuthorizationBola struct {
	BaseModule
	Target  string
	results []BrokenObjectLevelAuthorizationBolaResult

	// probe counters; guarded by Mu, read only after all workers finish.
	testedCount  int
	successCount int
	probeErrors  int
}

// NewBrokenObjectLevelAuthorizationBola creates a new instance.
func NewBrokenObjectLevelAuthorizationBola(target string) *BrokenObjectLevelAuthorizationBola {
	return &BrokenObjectLevelAuthorizationBola{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *BrokenObjectLevelAuthorizationBola) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// authzDenialVocabulary are value-level words that mark a "message"/"code"
// field as an access rejection rather than an ordinary data field.
var authzDenialVocabulary = []string{"unauthorized", "forbidden", "denied", "login required", "invalid", "please login", "log in"}

// authzQuotedValueForKey extracts the JSON string value bound to a quoted key
// (tolerating whitespace after the colon); ok is false when the key is absent
// or not followed by a string value.
func authzQuotedValueForKey(bodyLower, key string) (string, bool) {
	idx := 0
	for {
		i := strings.Index(bodyLower[idx:], key)
		if i == -1 {
			return "", false
		}
		rest := bodyLower[idx+i+len(key):]
		k := 0
		for k < len(rest) && (rest[k] == ' ' || rest[k] == ':' || rest[k] == '\t' || rest[k] == '\n' || rest[k] == '\r') {
			k++
		}
		rest = rest[k:]
		if strings.HasPrefix(rest, `"`) {
			v := rest[1:]
			if j := strings.IndexByte(v, '"'); j >= 0 {
				return v[:j], true
			}
		}
		idx += i + len(key)
	}
}

// authzErrorEnvelope reports whether a lowercase response body looks like an
// error envelope (top-level error/message/code keys) rather than a resource
// representation, so length-only judges do not flag 200-wrapped rejections.
// Bare quoted keys over-suppress genuine records (e.g. `"code": "US"`), so a
// rejection-shaped value is required: a non-empty "error" value, or a
// "message"/"code" value carrying denial vocabulary.
func authzErrorEnvelope(bodyLower string) bool {
	if errVal, ok := authzQuotedValueForKey(bodyLower, `"error"`); ok {
		trimmed := strings.TrimSpace(errVal)
		if trimmed != "" && trimmed != "null" {
			return true
		}
	}
	for _, key := range []string{`"message"`, `"code"`} {
		if val, ok := authzQuotedValueForKey(bodyLower, key); ok && containsAnyToken(val, authzDenialVocabulary) {
			return true
		}
	}
	return false
}

// authzPositiveObjectMarkers reports whether a lowercase body carries
// object-like fields (id/username/email/user/account/name), the positive
// signal required before a length-differential counts as exposed data.
func authzPositiveObjectMarkers(bodyLower string) bool {
	return containsAnyToken(bodyLower, []string{`"id"`, `"user"`, `"username"`, `"email"`, `"account"`, `"name"`})
}

// authzLoginWallDetected reports whether a lowercase body is structurally a
// login wall (password input, redirect to a login route, or explicit
// login-required text) instead of a bare keyword blocklist that suppresses
// genuine records mentioning "password".
func authzLoginWallDetected(bodyLower string) bool {
	if containsAnyToken(bodyLower, []string{
		`type="password"`, `type='password'`, `type=password`,
		`name="password"`, `name='password'`, `name=password`,
	}) {
		return true
	}
	if containsAnyToken(bodyLower, []string{
		`"/login"`, `"/signin"`, `"/sign-in"`, `"/log-in"`, `"/auth/login"`, `"/user/login"`, `"/accounts/login"`,
		`href=/login`, `action=/login`, `location.href="/login"`, `location="/login"`,
	}) {
		return true
	}
	return containsAnyToken(bodyLower, []string{
		"please log in", "please login", "login required", "log in to continue",
		"sign in to continue", "authentication required", "must be authenticated",
	})
}

func (m *BrokenObjectLevelAuthorizationBola) getBaselineLength(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target+"/api/users/999999999", nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusOK {
		// The sentinel ID resolved to a real object; its length is
		// indistinguishable from genuine records, so no reliable baseline
		// can be established from it.
		return 0, fmt.Errorf("baseline sentinel object 999999999 exists (HTTP 200); cannot establish baseline")
	}
	return len(body), nil
}

func (m *BrokenObjectLevelAuthorizationBola) Execute(ctx context.Context) ([]BrokenObjectLevelAuthorizationBolaResult, error) {
	m.results = make([]BrokenObjectLevelAuthorizationBolaResult, 0)
	m.testedCount = 0
	m.successCount = 0
	m.probeErrors = 0

	baselineLen, err := m.getBaselineLength(ctx)
	if err != nil {
		m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Unable to establish response-length baseline: "+err.Error()),
		})
		return m.results, nil
	}
	if baselineLen <= 0 {
		// A zero-length baseline makes the length-differential judge fire on
		// any non-empty 200; skip judging entirely rather than risk a false
		// positive.
		m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline response body is empty; length-differential judging is unreliable."),
		})
		return m.results, nil
	}

	// In a real attack, we'd take a known base ID and iterate up/down. Let's just fuzz IDs 1-10.
	jobs := make(chan string, 10)
	for i := 1; i <= 10; i++ {
		jobs <- strconv.Itoa(i)
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testID(ctx, id, baselineLen)
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
		if len(m.results) == 0 {
			// After probing ran, an empty result set is inconclusive — not a
			// clean scan — regardless of how many IDs returned HTTP 200: the
			// gates may have suppressed every response without confirming
			// anything.
			detail := fmt.Sprintf("Probing completed with no BOLA finding (%d IDs probed, %d returned HTTP 200, %d transport errors); no usable object access was confirmed.", m.testedCount, m.successCount, m.probeErrors)
			m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, detail),
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *BrokenObjectLevelAuthorizationBola) testID(ctx context.Context, id string, baselineLen int) {
	m.Mu.Lock()
	m.testedCount++
	m.Mu.Unlock()

	testURL := m.Target + "/api/users/" + id

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}
	m.Mu.Lock()
	m.successCount++
	m.Mu.Unlock()

	bodyLower := strings.ToLower(string(bodyBytes))
	// Gate the length-only judge: skip auth walls, 200-wrapped error
	// envelopes, and bodies without positive object markers.
	if authzLoginWallDetected(bodyLower) || authzErrorEnvelope(bodyLower) || !authzPositiveObjectMarkers(bodyLower) {
		return
	}

	// If we can read arbitrary users without auth, ensure it differs from baseline
	diff := len(bodyBytes) - baselineLen
	if diff < 0 {
		diff = -diff
	}

	isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500

	if isSignificantlyDifferent {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Unauthorized access to object at: "+testURL)
		m.results = append(m.results, BrokenObjectLevelAuthorizationBolaResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Unauthorized access to object at: " + testURL,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("broken_object_level_authorization_bola", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting BrokenObjectLevelAuthorizationBola on: %s", target))

		tester := NewBrokenObjectLevelAuthorizationBola(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
