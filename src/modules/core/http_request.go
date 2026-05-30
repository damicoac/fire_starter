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

	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}

	if m.BaseModule.Cookies != "" {
		req.Header.Set("Cookie", m.BaseModule.Cookies)
	}

	resp, err := m.BaseModule.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	return map[string]any{
		"status_code": resp.StatusCode,
		"headers":     respHeaders,
		"body":        string(respBody),
	}, nil
}

func init() {
	RegisterModule("http_request", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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

		onLog("HTTPRequest completed.")
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
