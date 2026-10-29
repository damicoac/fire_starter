package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type LoginCookieExtractor struct {
	BaseModule
	TargetURL   string
	Username    string
	Password    string
	ExtraFields map[string]string
}

func NewLoginCookieExtractor(targetURL, username, password string, extraFields map[string]string) *LoginCookieExtractor {
	return &LoginCookieExtractor{
		BaseModule:  *NewBaseModule(),
		TargetURL:   EnsureHTTPPrefix(targetURL),
		Username:    username,
		Password:    password,
		ExtraFields: extraFields,
	}
}

// loginCookieFailureMarkers are words that indicate an authentication failure page.
var loginCookieFailureMarkers = []string{"invalid", "incorrect", "wrong password", "login failed", "authentication failed", "bad credentials", "account locked", "locked", "denied"}

// loginCookieSuccessMarkers are positive authenticated-context markers.
var loginCookieSuccessMarkers = []string{"logout", "dashboard", "welcome", "signed in", "logged in", "my account", "profile"}

// loginCookiePasswordPattern matches quoted and unquoted password inputs.
var loginCookiePasswordPattern = regexp.MustCompile(`(?i)type\s*=\s*["']?password`)

// loginCookieFormView holds the hidden/submit inputs harvested from the login form.
type loginCookieFormView struct {
	fields      map[string]string
	hasPassword bool
}

// loginCookieParseFormFields tokenizes the (already size-capped) HTML and harvests
// hidden/submit fields only from the form that contains a password input —
// CSRF tokens from unrelated forms must not be posted to the login URL.
func loginCookieParseFormFields(data []byte) map[string]string {
	tokenizer := html.NewTokenizer(bytes.NewReader(data))
	var current *loginCookieFormView
	var chosen *loginCookieFormView

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			t := tokenizer.Token()
			switch t.Data {
			case "form":
				current = &loginCookieFormView{fields: make(map[string]string)}
			case "input":
				if current == nil {
					break // input outside any form: page-wide harvesting caused FPs
				}
				var name, value, inputType string
				for _, attr := range t.Attr {
					switch strings.ToLower(attr.Key) {
					case "type":
						inputType = strings.ToLower(attr.Val)
					case "name":
						name = attr.Val
					case "value":
						value = attr.Val
					}
				}
				if inputType == "password" {
					current.hasPassword = true
				}
				if (inputType == "hidden" || inputType == "submit") && name != "" {
					current.fields[name] = value
				}
			}
		case html.EndTagToken:
			t := tokenizer.Token()
			if t.Data == "form" && current != nil {
				if current.hasPassword && chosen == nil {
					chosen = current
				}
				current = nil
			}
		}
	}

	if chosen != nil {
		return chosen.fields
	}
	return map[string]string{}
}

// loginCookiePostSucceeded inspects the POST response for an authentication
// success signal: a 2xx (or non-login redirect) response that is not a
// re-rendered login form and does not carry failure markers.
func loginCookiePostSucceeded(statusCode int, body string, location string) (bool, string) {
	bodyLower := strings.ToLower(body)
	failed := containsAnyToken(bodyLower, loginCookieFailureMarkers) || loginCookiePasswordPattern.MatchString(bodyLower)

	if statusCode >= 200 && statusCode < 300 {
		if failed {
			return false, "POST returned 2xx but the body shows a login failure or re-rendered login form"
		}
		if containsAnyToken(bodyLower, loginCookieSuccessMarkers) {
			return true, ""
		}
		// A 2xx alone proves nothing: API endpoints and dashboards return 2xx
		// to unauthenticated callers too. Require an explicit
		// authentication-success marker before treating the POST as a login.
		return false, "POST returned 2xx without any authentication-success marker"
	}
	if statusCode >= 300 && statusCode < 400 {
		locLower := strings.ToLower(location)
		if strings.Contains(locLower, "login") || strings.Contains(locLower, "signin") || strings.Contains(locLower, "register") {
			return false, fmt.Sprintf("POST redirected back to a login page: %s", location)
		}
		if location != "" && !failed {
			return true, ""
		}
		return false, fmt.Sprintf("POST redirected with status %d and no authentication markers", statusCode)
	}
	return false, fmt.Sprintf("POST returned status %d", statusCode)
}

func (e *LoginCookieExtractor) Execute(ctx context.Context) ([]map[string]any, error) {
	client := NewHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects to capture cookies
	}

	// 1. Initial GET to fetch CSRF tokens and session cookies
	reqGet, err := http.NewRequestWithContext(ctx, "GET", e.TargetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	if cookies := e.BaseModule.GetCookies(); cookies != "" {
		reqGet.Header.Set("Cookie", cookies)
	}

	respGet, err := client.Do(reqGet)
	if err != nil {
		return nil, fmt.Errorf("failed to perform GET request: %w", err)
	}
	defer respGet.Body.Close()

	// Read the body with a hard cap before tokenizing (unbounded HTML was a
	// memory-exhaustion risk shared by every other consumer).
	getBodyBytes, err := ReadBoundedBody(respGet.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read GET response body: %w", err)
	}

	// Parse HTML for hidden inputs, scoped to the form holding the password.
	hiddenFields := loginCookieParseFormFields(getBodyBytes)

	// 2. Prepare POST form data
	formData := url.Values{}
	formData.Set("username", e.Username)
	formData.Set("password", e.Password)

	// Add extracted hidden fields
	for k, v := range hiddenFields {
		formData.Set(k, v)
	}

	// Add ExtraFields
	for k, v := range e.ExtraFields {
		formData.Set(k, v)
	}

	// 3. Perform POST Request
	reqPost, err := http.NewRequestWithContext(ctx, "POST", e.TargetURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if cookies := e.BaseModule.GetCookies(); cookies != "" {
		reqPost.Header.Set("Cookie", cookies)
	}

	respPost, err := client.Do(reqPost)
	if err != nil {
		return nil, fmt.Errorf("failed to perform POST request: %w", err)
	}
	defer respPost.Body.Close()

	postBodyBytes, err := ReadBoundedBody(respPost.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read POST response body: %w", err)
	}

	// 4. Verify the login actually succeeded before reporting extracted
	// cookies: a session cookie from the initial GET (populating the jar)
	// must not be mistaken for a successful authenticated login.
	succeeded, failReason := loginCookiePostSucceeded(respPost.StatusCode, string(postBodyBytes), respPost.Header.Get("Location"))

	// Read cookies from Jar
	var cookieJar []string
	if client.Jar != nil {
		if reqURL, err := url.Parse(e.TargetURL); err == nil {
			for _, c := range client.Jar.Cookies(reqURL) {
				cookieJar = append(cookieJar, fmt.Sprintf("%s=%s", c.Name, c.Value))
			}
		}
	}

	var results []map[string]any
	if succeeded && len(cookieJar) > 0 {
		// Persist the post-login jar contents into the shared BaseModule so
		// dependent modules (documented shared-cookie-jar persistence) can
		// reuse the authenticated session.
		e.SetCookies(strings.Join(cookieJar, "; "))
		results = append(results, map[string]any{
			"target":              e.TargetURL,
			"cookies":             cookieJar,
			"status":              "success",
			"hidden_fields_found": len(hiddenFields),
		})
	} else {
		reason := failReason
		if reason == "" && len(cookieJar) == 0 {
			reason = "no cookies extracted"
		}
		results = append(results, map[string]any{
			"target": e.TargetURL,
			"status": "failed",
			"reason": reason,
		})
	}

	return results, nil
}

func init() {
	RegisterModule("login_cookie_extractor", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		username, _ := payload["username"].(string)
		password, _ := payload["password"].(string)

		extraFields := make(map[string]string)
		if ext, ok := payload["extra_fields"].(map[string]any); ok {
			for k, v := range ext {
				extraFields[k] = fmt.Sprint(v)
			}
		}

		onLog(fmt.Sprintf("Starting LoginCookieExtractor on: %s", target))

		tester := NewLoginCookieExtractor(target, username, password, extraFields)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
