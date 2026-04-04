package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type LoginCookieExtractor struct {
	TargetURL string
	Username  string
	Password  string
}

func NewLoginCookieExtractor(targetURL, username, password string) *LoginCookieExtractor {
	return &LoginCookieExtractor{
		TargetURL: targetURL,
		Username:  username,
		Password:  password,
	}
}

func (e *LoginCookieExtractor) Execute(ctx context.Context) ([]map[string]any, error) {
	// First attempt as JSON
	payload := map[string]string{
		"username": e.Username,
		"password": e.Password,
	}
	
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.TargetURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects so we can capture cookies
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	cookies := resp.Header.Values("Set-Cookie")
	
	// If no cookies found with JSON, attempt with Form data
	if len(cookies) == 0 {
		formData := url.Values{}
		formData.Set("username", e.Username)
		formData.Set("password", e.Password)
		
		reqForm, err := http.NewRequestWithContext(ctx, "POST", e.TargetURL, strings.NewReader(formData.Encode()))
		if err == nil {
			reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			respForm, err := client.Do(reqForm)
			if err == nil {
				defer respForm.Body.Close()
				cookies = respForm.Header.Values("Set-Cookie")
			}
		}
	}

	var results []map[string]any
	if len(cookies) > 0 {
		results = append(results, map[string]any{
			"target":  e.TargetURL,
			"cookies": cookies,
			"status":  "success",
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
