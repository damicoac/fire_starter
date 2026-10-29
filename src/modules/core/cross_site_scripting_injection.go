package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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
	m.BaseModule.SetCookies(cookies)
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
// A bare substring match is not sufficient: reflections inside HTML comments,
// <textarea>/<title> RCDATA, or a still-open quoted attribute value are inert,
// and script-context payloads only execute between <script> and </script>.
type XSSValidator struct{}

// IsVulnerable checks if the payload reflected in the body constitutes an
// executable XSS in the declared reflection context.
func (v *XSSValidator) IsVulnerable(body string, payload XSSPayload) bool {
	lower := strings.ToLower(body)
	needle := strings.ToLower(payload.Value)
	start := 0
	for {
		rel := strings.Index(lower[start:], needle)
		if rel == -1 {
			return false
		}
		if xssReflectionExecutable(lower, start+rel, payload.Context) {
			return true
		}
		start += rel + 1
	}
}

var (
	// openQuotedAttrValueRe matches a tag prefix ending inside an open quoted
	// attribute value (e.g. `<input value="PROBE`).
	openQuotedAttrValueRe = regexp.MustCompile(`[^\s"'>=]+\s*=\s*("[^"]*|'[^']*)$`)
	// openUnquotedAttrValueRe matches a tag prefix ending inside an open
	// unquoted attribute value (e.g. `<a href=/next?q=PROBE`).
	openUnquotedAttrValueRe = regexp.MustCompile(`[^\s"'>=]+\s*=\s*[^\s"'<>]*$`)
)

// xssReflectionExecutable reports whether a verbatim payload reflection at the
// given offset would execute, considering the reflection context the payload
// was crafted for.
func xssReflectionExecutable(lower string, idx int, context ReflectionType) bool {
	if xssInsideHTMLComment(lower, idx) || xssInsideRCDATAElement(lower, idx) {
		return false
	}
	attrKind := xssOpenAttributeKind(lower[:idx])
	inScript := xssInsideScriptElement(lower, idx)
	switch context {
	case ContextScript:
		// The payload must sit in script data between <script> and </script>.
		return inScript && attrKind == ""
	case ContextAttribute:
		if inScript {
			// Reflected inside script data: the quote breakout never happens.
			return false
		}
		switch attrKind {
		case "quoted":
			// Payload starts with a quote that terminates the open value.
			return true
		case "unquoted":
			// In an unquoted attribute value the '>' inside the payload
			// terminates the tag, and the payload's <script> then parses as a
			// real element in the following content — executable.
			return true
		default:
			// Payload contains a full <script> element, so reflection in
			// element content executes as well.
			return true
		}
	default: // ContextHTML
		return attrKind == "" && !inScript
	}
}

func xssInsideHTMLComment(lower string, idx int) bool {
	lastOpen := strings.LastIndex(lower[:idx], "<!--")
	if lastOpen == -1 {
		return false
	}
	return strings.LastIndex(lower[:idx], "-->") < lastOpen
}

func xssInsideRCDATAElement(lower string, idx int) bool {
	for _, tag := range []string{"textarea", "title"} {
		openTag := "<" + tag
		lastOpen := strings.LastIndex(lower[:idx], openTag)
		if lastOpen == -1 {
			continue
		}
		rest := lower[lastOpen+len(openTag):]
		if rest != "" && rest[0] != '>' && rest[0] != '/' && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\n' && rest[0] != '\r' {
			continue
		}
		if strings.Contains(lower[lastOpen:idx], "</"+tag) {
			continue
		}
		return true
	}
	return false
}

func xssInsideScriptElement(lower string, idx int) bool {
	lastOpen := strings.LastIndex(lower[:idx], "<script")
	if lastOpen == -1 {
		return false
	}
	rest := lower[lastOpen+len("<script"):]
	if rest != "" && rest[0] != '>' && rest[0] != '/' && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\n' && rest[0] != '\r' {
		return false
	}
	return !strings.Contains(lower[lastOpen:idx], "</script")
}

// xssOpenAttributeKind reports whether the tag prefix ends inside an open
// attribute value, and whether that value is quoted.
func xssOpenAttributeKind(precedingLower string) string {
	tagStart := strings.LastIndex(precedingLower, "<")
	if tagStart == -1 {
		return ""
	}
	if strings.LastIndex(precedingLower, ">") > tagStart {
		return ""
	}
	tag := precedingLower[tagStart:]
	if openQuotedAttrValueRe.MatchString(tag) {
		return "quoted"
	}
	if openUnquotedAttrValueRe.MatchString(tag) {
		return "unquoted"
	}
	return ""
}

var xssContextPayloads = []XSSPayload{
	{"<script>alert(1)</script>", ContextHTML},
	{"\"><script>alert(1)</script>", ContextAttribute},
	{"'-alert(1)-'", ContextScript},
}

// xssHTMLContentTypes are the only response content types where a reflected
// payload is parsed as markup. JSON endpoints legally return raw markup inside
// JSON strings, so they must not be judged as vulnerable.
func xssHTMLContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/html" || ct == "application/xhtml+xml"
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
	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		headers.Set("Cookie", cookies)
	}

	// 1. Discover all input vectors.
	vectors, _, err := m.DiscoverVectors(parsedURL, nil, "", headers)
	if err != nil {
		return m.results, err
	}
	if len(vectors) == 0 {
		vectors = append(vectors,
			InputVector{Type: VectorQueryParam, Key: "q", Value: ""},
			InputVector{Type: VectorQueryParam, Key: "search", Value: ""},
			InputVector{Type: VectorQueryParam, Key: "name", Value: ""},
		)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.MaxThreads)
	validator := &XSSValidator{}

	for _, vector := range vectors {
		// 2. For each vector, discover its reflection contexts. A vector that
		// is not reflected gives no usable reflection context: firing payloads
		// with an invented ContextHTML default produced false positives, so
		// the vector is skipped. A failed probe is reported as inconclusive.
		reflections, reflectionErr := m.DiscoverReflection(ctx, parsedURL, vector)
		if reflectionErr != nil {
			m.Mu.Lock()
			m.noteInconclusive(fmt.Sprintf("Reflection probe failed for %s parameter '%s': %v",
				vector.Type, vector.Key, reflectionErr))
			m.Mu.Unlock()
			continue
		}
		if len(reflections) == 0 {
			continue
		}

		// 3. For each distinct context, run only the relevant XSS payloads.
		seenContexts := make(map[ReflectionType]bool)
		for _, reflection := range reflections {
			if seenContexts[reflection.Type] {
				continue
			}
			seenContexts[reflection.Type] = true
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

// noteInconclusive records an inconclusive row carrying a failure detail. It
// must be called with m.Mu held; duplicate details are collapsed so repeated
// probe failures do not flood the report.
func (m *CrossSiteScriptingInjection) noteInconclusive(detail string) {
	for _, r := range m.results {
		if r.Status == "inconclusive" && r.Detail == formatEvidenceDetail(EvidenceWeak, detail) {
			return
		}
	}
	m.results = append(m.results, CrossSiteScriptingInjectionResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceWeak, false),
		Detail: formatEvidenceDetail(EvidenceWeak, detail),
	})
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
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Payload request could not be built for %s parameter '%s': %v",
			vector.Type, vector.Key, err))
		m.Mu.Unlock()
		return
	}

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Payload request to %s parameter '%s' failed: %v",
			vector.Type, vector.Key, err))
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Response body read failed for %s parameter '%s': %v",
			vector.Type, vector.Key, err))
		m.Mu.Unlock()
		return
	}

	// Content-Type gate: only HTML-ish responses parse reflected markup.
	if !xssHTMLContentType(resp.Header.Get("Content-Type")) {
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Endpoint for %s parameter '%s' returned Content-Type %q; XSS reflection is only judged on text/html responses.",
			vector.Type, vector.Key, resp.Header.Get("Content-Type")))
		m.Mu.Unlock()
		return
	}

	bodyStr := string(bodyBytes)

	// 4. Verify reflection of the payload (unescaped) in the response using the validator.
	if !validator.IsVulnerable(bodyStr, payload) {
		return
	}

	m.Mu.Lock()
	detail := fmt.Sprintf("XSS found in %s parameter '%s' (Context: %s). Payload reflected unescaped in an executable position: %s",
		vector.Type, vector.Key, payload.Context, payload.Value)
	tier := EvidenceConfirmed
	m.RecordPoC(req, nil, detail)
	m.results = append(m.results, CrossSiteScriptingInjectionResult{
		Target: m.Target,
		Status: statusFromEvidence(tier, false),
		Detail: formatEvidenceDetail(tier, detail),
	})
	m.Mu.Unlock()
}

func init() {
	RegisterModule("cross_site_scripting_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
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
