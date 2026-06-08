package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	Target  string
	results []PasswordSprayingResult
}

// NewPasswordSpraying creates a new instance.
func NewPasswordSpraying(target string) *PasswordSpraying {
	return &PasswordSpraying{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
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

func (m *PasswordSpraying) getBaselineAuthBypass(ctx context.Context) (bool, int) {
	body := "username=invalid_user_12345&password=invalid_password_12345"
	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader(body))
	if err != nil {
		return false, 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.Client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

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
			return true, len(bodyBytes)
		}
		return false, len(bodyBytes)
	}
	return false, len(bodyBytes)
}

func (m *PasswordSpraying) Execute(ctx context.Context) ([]PasswordSprayingResult, error) {
	m.results = make([]PasswordSprayingResult, 0)

	baselineAuthBypass, baselineLen := m.getBaselineAuthBypass(ctx)

	jobs := make(chan string, len(sprayUsernames))
	for _, u := range sprayUsernames {
		jobs <- u
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for username := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testUsername(ctx, username, baselineAuthBypass, baselineLen)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *PasswordSpraying) testUsername(ctx context.Context, username string, baselineAuthBypass bool, baselineLen int) {
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

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := strings.ToLower(string(bodyBytes))

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

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
