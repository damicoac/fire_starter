package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
		TargetURL:   EnsureHTTPPrefix(targetURL),
		Username:    username,
		Password:    password,
		ExtraFields: extraFields,
	}
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

	if e.BaseModule.Cookies != "" {
		reqGet.Header.Set("Cookie", e.BaseModule.Cookies)
	}

	respGet, err := client.Do(reqGet)
	if err != nil {
		return nil, fmt.Errorf("failed to perform GET request: %w", err)
	}
	defer respGet.Body.Close()

	// Parse HTML for hidden inputs
	hiddenFields := make(map[string]string)
	tokenizer := html.NewTokenizer(respGet.Body)
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := tokenizer.Token()
			if t.Data == "input" {
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
				if (inputType == "hidden" || inputType == "submit") && name != "" {
					hiddenFields[name] = value
				}
			}
		}
	}

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

	if e.BaseModule.Cookies != "" {
		reqPost.Header.Set("Cookie", e.BaseModule.Cookies)
	}

	respPost, err := client.Do(reqPost)
	if err != nil {
		return nil, fmt.Errorf("failed to perform POST request: %w", err)
	}
	defer respPost.Body.Close()

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
	if len(cookieJar) > 0 {
		results = append(results, map[string]any{
			"target":              e.TargetURL,
			"cookies":             cookieJar,
			"status":              "success",
			"hidden_fields_found": len(hiddenFields),
		})
	} else {
		results = append(results, map[string]any{
			"target": e.TargetURL,
			"status": "failed",
			"reason": "no cookies extracted",
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
