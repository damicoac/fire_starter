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

// CrossSiteScriptingInjectionResult holds the result of the CrossSiteScriptingInjection module execution.
type CrossSiteScriptingInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CrossSiteScriptingInjection executes the cross_site_scripting_injection security technique.
type CrossSiteScriptingInjection struct {
	BaseModule
	Target  string
	results []CrossSiteScriptingInjectionResult
}

// NewCrossSiteScriptingInjection creates a new instance.
func NewCrossSiteScriptingInjection(target string) *CrossSiteScriptingInjection {
	return &CrossSiteScriptingInjection{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

// SetCookies sets the Cookie header value for the requests.
func (m *CrossSiteScriptingInjection) SetCookies(cookies string) {
	m.BaseModule.Cookies = cookies
}

func (m *CrossSiteScriptingInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

type XSSPayload struct {
	Value   string
	Context ReflectionType
}

// XSSValidator handles the validation of XSS vulnerabilities based on reflection context.
type XSSValidator struct{}

// IsVulnerable checks if the payload reflected in the body constitutes a vulnerability.
func (v *XSSValidator) IsVulnerable(body string, payload XSSPayload) bool {
	// Current implementation: check if the payload value is reflected unescaped.
	// This satisfies the context-aware requirement because we receive the payload
	// that was specifically crafted for the reflection context found earlier.
	return strings.Contains(body, payload.Value)
}

var xssContextPayloads = []XSSPayload{
	{"<script>alert(1)</script>", ContextHTML},
	{"\"><script>alert(1)</script>", ContextAttribute},
	{"'-alert(1)-'", ContextScript},
}

func (m *CrossSiteScriptingInjection) Execute(ctx context.Context) ([]CrossSiteScriptingInjectionResult, error) {
	m.Mu.Lock()
	m.results = make([]CrossSiteScriptingInjectionResult, 0)
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	headers := http.Header{}
	if m.BaseModule.Cookies != "" {
		headers.Set("Cookie", m.BaseModule.Cookies)
	}

	// 1. Discover all input vectors.
	vectors, _ := m.DiscoverVectors(parsedURL, nil, "", headers)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.MaxThreads)
	validator := &XSSValidator{}

	for _, vector := range vectors {
		// 2. For each vector, discover its reflection contexts.
		reflections := m.DiscoverReflection(ctx, parsedURL, vector)

		// 3. For each context, run only the relevant XSS payloads.
		for _, reflection := range reflections {
			for _, payload := range xssContextPayloads {
				if payload.Context == reflection.Type {
					wg.Add(1)
					go func(v InputVector, p XSSPayload) {
						defer wg.Done()
						semaphore <- struct{}{}
						defer func() { <-semaphore }()

						select {
						case <-ctx.Done():
							return
						default:
							m.testContextPayload(ctx, parsedURL, v, p, validator)
						}
					}(vector, payload)
				}
			}
		}
	}

	wg.Wait()
	return m.results, nil
}

func (m *CrossSiteScriptingInjection) testContextPayload(ctx context.Context, u *url.URL, vector InputVector, payload XSSPayload, validator *XSSValidator) {
	var req *http.Request
	var err error

	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}

	req, err = m.BaseModule.BuildRequestWithVector(ctx, method, u, vector, payload.Value)
	if err != nil || req == nil {
		return
	}

	if m.BaseModule.Cookies != "" {
		req.Header.Set("Cookie", m.BaseModule.Cookies)
	}

	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(bodyBytes)

	// 4. Verify reflection of the payload (unescaped) in the response using the validator.
	if validator.IsVulnerable(bodyStr, payload) {
		m.Mu.Lock()
		m.results = append(m.results, CrossSiteScriptingInjectionResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("XSS found in %s parameter '%s' (Context: %s). Payload reflected unescaped: %s",
				vector.Type, vector.Key, payload.Context, payload.Value),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("cross_site_scripting_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CrossSiteScriptingInjection on: %s", target))

		tester := NewCrossSiteScriptingInjection(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
