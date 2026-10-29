package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPRequestModule struct {
	BaseModule
	Target  string
	Method  string
	Body    string
	Headers map[string]string
	log     func(string)
}

func NewHTTPRequestModule(target, method, body string, headers map[string]string) *HTTPRequestModule {
	if method == "" {
		method = "GET"
	}
	return &HTTPRequestModule{
		Target:  EnsureHTTPPrefix(target),
		Method:  strings.ToUpper(method),
		Body:    body,
		Headers: headers,
		BaseModule: BaseModule{
			Client: NewHTTPClient(15 * time.Second),
		},
	}
}

func (m *HTTPRequestModule) Execute(ctx context.Context) (map[string]any, error) {
	var reqBody io.Reader
	if m.Body != "" {
		reqBody = bytes.NewBufferString(m.Body)
	}

	req, err := http.NewRequestWithContext(ctx, m.Method, m.Target, reqBody)
	if err != nil {
		return nil, err
	}

	callerSuppliedCookie := false
	for k := range m.Headers {
		if strings.EqualFold(k, "Cookie") {
			callerSuppliedCookie = true
		}
	}

	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		if callerSuppliedCookie {
			// Merge session cookies without discarding the caller's Cookie header.
			req.Header.Add("Cookie", cookies)
		} else {
			req.Header.Set("Cookie", cookies)
		}
	}

	resp, err := m.BaseModule.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, truncated, err := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, err
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	result := map[string]any{
		"status_code": resp.StatusCode,
		"headers":     respHeaders,
		"body":        string(respBody),
		"truncated":   truncated,
	}
	if m.log != nil {
		m.log("HTTPRequest completed.")
	}
	return result, nil
}

func init() {
	RegisterModule("http_request", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		method := PayloadString(payload, "method", "GET")
		body := PayloadString(payload, "body", "")

		headers := make(map[string]string)
		if h, ok := payload["headers"].(map[string]any); ok {
			for k, v := range h {
				headers[k] = fmt.Sprint(v)
			}
		}

		onLog(fmt.Sprintf("Starting HTTPRequest on: %s %s", method, target))

		tester := NewHTTPRequestModule(target, method, body, headers)
		tester.log = onLog

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
