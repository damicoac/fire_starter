package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OSCmdType string

const (
	CmdReflection OSCmdType = "reflection"
	CmdTimeBased  OSCmdType = "time_based"
	CmdBoolean    OSCmdType = "boolean"
)

type OSPayload struct {
	Value string
	Type  OSCmdType
	OS    string // "unix" or "windows"
}

type OSValidator struct {
	Threshold        time.Duration
	BaselineDuration time.Duration
	BaselineBody     string
}

func (v *OSValidator) IsVulnerable(resp *http.Response, body string, payload OSPayload, duration time.Duration) bool {
	switch payload.Type {
	case CmdReflection:
		// Look for common OS command output patterns
		indicators := []string{
			"uid=", "gid=", "groups=", // from 'id'
			"Volume in drive", "Directory of", // from 'dir'
			"drwxr-xr-x", "rw-r--r--", // from 'ls -l'
			"Windows IP Configuration",          // from 'ipconfig'
			"eth0", "inet addr:", "inet6 addr:", // from 'ifconfig'
		}
		for _, indicator := range indicators {
			// An indicator already present in the same vector's canary baseline
			// is static page content, not injected command output.
			if strings.Contains(body, indicator) && !strings.Contains(v.BaselineBody, indicator) {
				return true
			}
		}
	case CmdTimeBased:
		minThreshold := v.Threshold
		if v.BaselineDuration > 0 {
			minThreshold = v.BaselineDuration + v.Threshold
		}
		if duration >= minThreshold {
			return true
		}
	case CmdBoolean:
		// Boolean detection: check for the marker, but reject if already present in baseline
		marker := "VULNERABLE"
		if strings.Contains(body, marker) {
			if v.BaselineBody != "" && strings.Contains(v.BaselineBody, marker) {
				return false
			}
			return true
		}
	}
	return false
}

// OSCommandInjectionResult holds the result of the OSCommandInjection module execution.
type OSCommandInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// OSCommandInjection executes the os_command_injection security technique.
type OSCommandInjection struct {
	BaseModule
	Target    string
	Threshold time.Duration
	results   []OSCommandInjectionResult
	probeErrs []string

	// Timing baseline: minimum of several benign samples, so a single slow
	// response does not inflate the time-based detection threshold.
	baselineDuration time.Duration
	// Per-vector canary baselines (benign value on the SAME key) cached so a
	// reflecting page cannot be mistaken for command execution.
	baselines sync.Map
}

// NewOSCommandInjection creates a new instance of OSCommandInjection.
func NewOSCommandInjection(target string) *OSCommandInjection {
	return &OSCommandInjection{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(15 * time.Second),
			MaxThreads: 5,
		},
		Target:    EnsureHTTPPrefix(target),
		Threshold: 4 * time.Second, // Default threshold
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *OSCommandInjection) SetCookies(cookies string) {
	m.BaseModule.SetCookies(cookies)
}

func (m *OSCommandInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

// SetThreshold sets the time threshold for time-based detection.
func (m *OSCommandInjection) SetThreshold(threshold time.Duration) {
	m.Threshold = threshold
}

// osCanarySuffix is a benign marker appended to the vector value for the
// per-vector baseline request. It must never contain a substring that any
// payload, indicator, or verify token also contains ("id", "echo", "sleep", ...).
const osCanarySuffix = "fsbaseline9zq"

var osPayloads = []OSPayload{
	// Unix Reflection
	{Value: "; id", Type: CmdReflection, OS: "unix"},
	{Value: "| id", Type: CmdReflection, OS: "unix"},
	{Value: "`id`", Type: CmdReflection, OS: "unix"},
	{Value: "$(id)", Type: CmdReflection, OS: "unix"},

	// Unix Time-based
	{Value: "; sleep 5", Type: CmdTimeBased, OS: "unix"},
	{Value: "& sleep 5", Type: CmdTimeBased, OS: "unix"},
	{Value: "| sleep 5", Type: CmdTimeBased, OS: "unix"},

	// Unix Boolean
	{Value: " && echo VULNERABLE", Type: CmdBoolean, OS: "unix"},
	{Value: " || echo VULNERABLE", Type: CmdBoolean, OS: "unix"},
	{Value: "; echo VULNERABLE", Type: CmdBoolean, OS: "unix"},

	// Windows Reflection
	{Value: "& whoami", Type: CmdReflection, OS: "windows"},
	{Value: "| whoami", Type: CmdReflection, OS: "windows"},
	{Value: "& ipconfig", Type: CmdReflection, OS: "windows"}, // matches "Windows IP Configuration"
	{Value: "& dir", Type: CmdReflection, OS: "windows"},      // matches "Volume in drive" / "Directory of"

	// Windows Time-based
	{Value: "& timeout /t 5", Type: CmdTimeBased, OS: "windows"},

	// Windows Boolean
	{Value: " && echo VULNERABLE", Type: CmdBoolean, OS: "windows"},
	{Value: " || echo VULNERABLE", Type: CmdBoolean, OS: "windows"},
}

func (m *OSCommandInjection) Execute(ctx context.Context) ([]OSCommandInjectionResult, error) {
	m.Mu.Lock()
	m.results = make([]OSCommandInjectionResult, 0)
	m.probeErrs = nil
	m.Mu.Unlock()
	m.baselines = sync.Map{}
	m.baselineDuration = 0

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		headers.Set("Cookie", cookies)
	}

	// Discover vectors
	vectors, _, err := m.DiscoverVectors(parsedURL, nil, "", headers)
	if err != nil {
		return nil, err
	}

	// sendPayload supports query, form, and JSON vectors only: exclude header
	// and path-segment vectors instead of generating swallowed errors.
	testable := vectors[:0]
	hasQueryOrBody := false
	for _, v := range vectors {
		switch v.Type {
		case VectorQueryParam, VectorFormBody, VectorJSONBody:
			hasQueryOrBody = true
			testable = append(testable, v)
		}
	}
	vectors = testable

	if !hasQueryOrBody {
		// Default vectors if none discovered
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "cmd", Value: ""})
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "exec", Value: ""})
	}

	// Multi-sample timing baseline (minimum of 3 benign requests). A failed
	// baseline previously fell back to the raw threshold; now every failure is
	// captured and a fully failed baseline aborts with an inconclusive row.
	baselineDuration, baselineErr := m.measureBaseline(ctx, parsedURL)
	if baselineErr != nil {
		m.Mu.Lock()
		m.results = append(m.results, OSCommandInjectionResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline request failed: %v", baselineErr)),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	m.baselineDuration = baselineDuration

	type job struct {
		vector  InputVector
		payload OSPayload
	}

	jobChan := make(chan job, len(vectors)*len(osPayloads))
	for _, v := range vectors {
		for _, p := range osPayloads {
			jobChan <- job{vector: v, payload: p}
		}
	}
	close(jobChan)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
					m.testVector(ctx, parsedURL, j.vector, j.payload)
				}
			}
		}()
	}

	wg.Wait()

	// A mid-run cancellation previously fell through to a nil error with a
	// partial (often empty) result slice; surface the cancellation instead.
	if ctxErr := ctx.Err(); ctxErr != nil {
		m.Mu.Lock()
		results := m.results
		m.Mu.Unlock()
		return results, ctxErr
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.results) == 0 && len(m.probeErrs) > 0 {
		// Every probe failed on transport/build errors: report it instead of
		// letting an unreachable target look like a clean scan.
		m.results = append(m.results, OSCommandInjectionResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All probes failed; first error: %s", m.probeErrs[0])),
		})
	}
	return m.results, nil
}

// measureBaseline issues several benign requests and returns the minimum
// observed duration so the time-based judge is baseline-adjusted.
func (m *OSCommandInjection) measureBaseline(ctx context.Context, u *url.URL) (time.Duration, error) {
	minDuration := time.Duration(0)
	var lastErr error
	for range 3 {
		select {
		case <-ctx.Done():
			return minDuration, ctx.Err()
		default:
		}
		duration, _, _, err := m.sendPayload(ctx, u, InputVector{Type: VectorQueryParam, Key: "_fs_probe", Value: "1"}, "")
		if err != nil {
			lastErr = err
			continue
		}
		if minDuration == 0 || duration < minDuration {
			minDuration = duration
		}
	}
	if minDuration == 0 && lastErr != nil {
		return 0, lastErr
	}
	return minDuration, nil
}

// vectorBaseline sends the same vector with a benign canary value on the SAME
// key and caches the response body. A page that reflects parameter values has
// the canary in its baseline body, so marker hits that merely echo the payload
// text can be rejected instead of confirmed as command execution.
func (m *OSCommandInjection) vectorBaseline(ctx context.Context, u *url.URL, vector InputVector) (string, bool) {
	cacheKey := string(vector.Type) + ":" + vector.Key
	if cached, ok := m.baselines.Load(cacheKey); ok {
		if s, ok := cached.(string); ok {
			return s, true
		}
		return "", false
	}
	_, body, _, err := m.sendPayload(ctx, u, vector, osCanarySuffix)
	if err != nil {
		m.recordProbeError(fmt.Errorf("baseline for vector %s/%s: %w", vector.Type, vector.Key, err))
		return "", false
	}
	m.baselines.Store(cacheKey, body)
	return body, true
}

func (m *OSCommandInjection) testVector(ctx context.Context, u *url.URL, vector InputVector, payload OSPayload) {
	baseBody, ok := m.vectorBaseline(ctx, u, vector)
	if !ok {
		return
	}

	duration, body, resp, err := m.sendPayload(ctx, u, vector, payload.Value)
	if err != nil {
		m.recordProbeError(fmt.Errorf("probe %s/%s with %q: %w", vector.Type, vector.Key, payload.Value, err))
		return
	}

	validator := &OSValidator{
		Threshold:        m.Threshold,
		BaselineDuration: m.baselineDuration,
		BaselineBody:     baseBody,
	}

	if !validator.IsVulnerable(nil, body, payload, duration) {
		return
	}

	// Multi-stage verification
	switch payload.Type {
	case CmdTimeBased:
		// Differential timing analysis: try a "fast" payload.
		// Replace "sleep 5" or "timeout /t 5" with 0.
		fastValue := payload.Value
		if strings.Contains(fastValue, "sleep 5") {
			fastValue = strings.Replace(fastValue, "sleep 5", "sleep 0", 1)
		} else if strings.Contains(fastValue, "timeout /t 5") {
			fastValue = strings.Replace(fastValue, "timeout /t 5", "timeout /t 0", 1)
		}

		fastDuration, _, _, err := m.sendPayload(ctx, u, vector, fastValue)
		if err != nil {
			m.recordProbeError(fmt.Errorf("fast probe %s/%s: %w", vector.Type, vector.Key, err))
			return
		}

		// Baseline-adjusted fast check: if the fast payload is also slower than
		// the baseline plus the threshold, the server is just slow and the
		// detection is a false positive.
		if fastDuration >= m.Threshold && (m.baselineDuration == 0 || fastDuration >= m.baselineDuration+m.Threshold) {
			return
		}
	case CmdBoolean, CmdReflection:
		// A page that echoes parameter values would reflect the payload text
		// verbatim; a marker hit alongside the raw payload text is reflection,
		// not command execution.
		if strings.Contains(baseBody, osCanarySuffix) && strings.Contains(body, payload.Value) {
			return
		}

		// Chained command verification: verify with a different token to ensure it's not a fluke or static response
		verifyToken := "VERIFIED"
		if strings.Contains(baseBody, verifyToken) {
			verifyToken = "VERIFIED_CANARY_CHECK"
		}
		verifyValue := strings.Replace(payload.Value, "VULNERABLE", verifyToken, 1)
		for _, cmd := range []string{"id", "whoami", "ipconfig", "dir"} {
			if strings.Contains(verifyValue, cmd) {
				verifyValue = strings.Replace(verifyValue, cmd, "echo "+verifyToken, 1)
				break
			}
		}

		_, verifyBody, _, err := m.sendPayload(ctx, u, vector, verifyValue)
		if err != nil {
			m.recordProbeError(fmt.Errorf("verify probe %s/%s: %w", vector.Type, vector.Key, err))
			return
		}

		if !strings.Contains(verifyBody, verifyToken) {
			return
		}
		if strings.Contains(baseBody, verifyToken) {
			return
		}
	}

	detail := fmt.Sprintf("OS injection successful in %s '%s' using %s %s payload: %s", vector.Type, vector.Key, payload.OS, payload.Type, payload.Value)
	m.RecordPoC(resp.Request, nil, detail)

	m.Mu.Lock()
	m.results = append(m.results, OSCommandInjectionResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceConfirmed, false),
		Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
	})
	m.Mu.Unlock()
}

func (m *OSCommandInjection) recordProbeError(err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	// Cap the stored details so a mass transport failure cannot balloon memory.
	if len(m.probeErrs) < 8 {
		m.probeErrs = append(m.probeErrs, err.Error())
	}
}

func (m *OSCommandInjection) sendPayload(ctx context.Context, u *url.URL, vector InputVector, payloadValue string) (time.Duration, string, *http.Response, error) {
	testValue := vector.Value + payloadValue

	var req *http.Request
	var err error

	switch vector.Type {
	case VectorQueryParam:
		newU := *u
		// rawValuesWithPayload keeps the other parameters intact and splices
		// already-percent-encoded payloads verbatim.
		newU.RawQuery = rawValuesWithPayload(newU.Query(), vector.Key, testValue)
		req, err = http.NewRequestWithContext(ctx, "GET", newU.String(), nil)

	case VectorFormBody:
		values := url.Values{}
		m.Mu.Lock()
		origBody := append([]byte(nil), m.BaseModule.OriginalBody...)
		m.Mu.Unlock()
		if len(origBody) > 0 {
			var parseErr error
			values, parseErr = url.ParseQuery(string(origBody))
			if parseErr != nil {
				// Sending a body holding only the payload would corrupt the
				// request the target issued; fail the vector instead.
				return 0, "", nil, fmt.Errorf("failed to parse original form body for vector %q: %w", vector.Key, parseErr)
			}
		}
		bodyStr := rawValuesWithPayload(values, vector.Key, testValue)
		req, err = http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(bodyStr))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

	case VectorJSONBody:
		m.Mu.Lock()
		origBody := append([]byte(nil), m.BaseModule.OriginalBody...)
		m.Mu.Unlock()
		var newBody []byte
		if len(origBody) > 0 {
			var mutateErr error
			newBody, mutateErr = m.MutateJSON(origBody, vector.JSONPath, testValue)
			if mutateErr != nil {
				return 0, "", nil, fmt.Errorf("failed to mutate JSON body for vector %q: %w", vector.Key, mutateErr)
			}
		} else {
			newBody, _ = json.Marshal(map[string]any{vector.Key: testValue})
		}
		req, err = http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(string(newBody)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}

	default:
		return 0, "", nil, fmt.Errorf("unsupported vector type: %s", vector.Type)
	}

	if err != nil || req == nil {
		if err == nil {
			err = fmt.Errorf("failed to build request for vector type %s", vector.Type)
		}
		return 0, "", nil, err
	}

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	start := time.Now()
	resp, err := m.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	// Propagate read failures instead of silently judging on a partial body.
	bodyBytes, _, readErr := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		return 0, "", nil, fmt.Errorf("failed to read response body: %w", readErr)
	}
	bodyStr := string(bodyBytes)

	return duration, bodyStr, resp, nil
}

func init() {
	RegisterModule("os_command_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting OSCommandInjection on: %s", target))

		tester := NewOSCommandInjection(target)
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
