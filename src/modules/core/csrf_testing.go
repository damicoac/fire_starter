package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CSRFTestingResult holds the result of the CSRFTesting module execution.
type CSRFTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CSRFTesting executes the csrf_testing security technique.
// Probing is restricted to POST forms discovered on the target page; the
// module never POSTs to guessed endpoints. Judging is differential: the form
// is submitted with and without its discovered token fields and the responses
// are compared via EvaluateDifferentialEvidence.
type CSRFTesting struct {
	BaseModule
	Target  string
	results []CSRFTestingResult
}

// NewCSRFTesting creates a new instance.
func NewCSRFTesting(target string) *CSRFTesting {
	return &CSRFTesting{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

// SetCookies implements SessionAware so the executor can deliver session
// cookies for authenticated CSRF assessments.
func (m *CSRFTesting) SetCookies(cookies string) {
	m.BaseModule.SetCookies(cookies)
}

func (m *CSRFTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

type csrfForm struct {
	Action        string // absolute URL of the form action
	VisibleFields map[string]string
	HiddenFields  map[string]string // token candidates
}

var (
	csrfFormRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	csrfInputRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	csrfAttrRe  = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)\b` + name + `\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	}
	csrfMethodRe  = csrfAttrRe("method")
	csrfActionRe  = csrfAttrRe("action")
	csrfNameRe    = csrfAttrRe("name")
	csrfTypeRe    = csrfAttrRe("type")
	csrfValueRe   = csrfAttrRe("value")
	csrfMarkerVal = "csrf_probe_marker"
)

// csrfAttrValue extracts an attribute value from a tag string.
func csrfAttrValue(re *regexp.Regexp, tag string) string {
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[2]
	}
	if m[3] != "" {
		return m[3]
	}
	return m[4]
}

// csrfParseForms extracts POST forms with their fields from page HTML,
// resolving relative actions against the page URL.
func csrfParseForms(pageHTML string, base *url.URL) []csrfForm {
	var forms []csrfForm
	for _, fm := range csrfFormRe.FindAllStringSubmatch(pageHTML, -1) {
		tag := fm[1]
		inner := fm[2]
		method := strings.TrimSpace(csrfAttrValue(csrfMethodRe, tag))
		if method == "" {
			method = "get"
		}
		if !strings.EqualFold(method, "post") {
			continue
		}
		form := csrfForm{
			VisibleFields: make(map[string]string),
			HiddenFields:  make(map[string]string),
		}
		action := strings.TrimSpace(csrfAttrValue(csrfActionRe, tag))
		if action == "" {
			form.Action = base.String()
		} else if actionURL, err := base.Parse(action); err == nil {
			form.Action = actionURL.String()
		} else {
			continue
		}
		for _, in := range csrfInputRe.FindAllStringSubmatch(inner, -1) {
			itag := in[1]
			name := strings.TrimSpace(csrfAttrValue(csrfNameRe, itag))
			if name == "" {
				continue
			}
			value := csrfAttrValue(csrfValueRe, itag)
			inputType := strings.ToLower(strings.TrimSpace(csrfAttrValue(csrfTypeRe, itag)))
			if inputType == "hidden" {
				form.HiddenFields[name] = value
			} else {
				form.VisibleFields[name] = value
			}
		}
		forms = append(forms, form)
	}
	return forms
}

// csrfNoRedirectClient returns a client that does not follow redirects so the
// 3xx status, Location, and Set-Cookie headers of the first POST response hop
// remain visible for judging.
func (m *CSRFTesting) csrfNoRedirectClient() *http.Client {
	base := m.Client
	if base == nil {
		base = http.DefaultClient
	}
	c := *base
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

// doRequest performs an HTTP request with session cookies attached.
func (m *CSRFTesting) doRequest(ctx context.Context, method, targetURL, contentType, body string) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	return m.csrfNoRedirectClient().Do(req)
}

func (m *CSRFTesting) Execute(ctx context.Context) ([]CSRFTestingResult, error) {
	m.Mu.Lock()
	m.results = make([]CSRFTestingResult, 0)
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	// Step 1: GET the target page to discover its POST forms. No guessed
	// endpoints are probed; blind state-changing POSTs are never sent.
	getResp, err := m.doRequest(ctx, "GET", parsedURL.String(), "", "")
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline GET failed: "+err.Error()),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	defer getResp.Body.Close()

	getBodyBytes, readErr := ReadBoundedBody(getResp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		m.Mu.Lock()
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline GET body read failed: "+readErr.Error()),
		})
		m.Mu.Unlock()
		return m.results, nil
	}
	getBody := string(getBodyBytes)

	if getResp.StatusCode >= 300 {
		m.Mu.Lock()
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("Baseline GET returned status %d; no POST forms could be discovered for CSRF assessment.", getResp.StatusCode)),
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	forms := csrfParseForms(getBody, parsedURL)
	if len(forms) == 0 {
		m.Mu.Lock()
		m.results = append(m.results, CSRFTestingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "No POST forms were discovered on the target page; CSRF protection could not be assessed."),
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	// Step 2: submit each discovered form with and without its token fields.
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, m.MaxThreads)
	for _, form := range forms {
		wg.Add(1)
		go func(f csrfForm) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
				m.testForm(ctx, f, getBody)
			}
		}(form)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

// csrfClassifyResponse maps a POST response to accepted/rejected/uncertain for
// differential judging. 3xx responses are inconclusive unless the Location
// targets an application page (same host, not a login/error path).
func csrfClassifyResponse(status int, body, location, appHost string) (accepted, rejected, uncertain bool, effective string) {
	switch {
	case status >= 200 && status < 300:
		return true, false, false, body
	case status >= 300 && status < 400:
		if csrfAppRedirect(location, appHost) {
			return true, false, false, "redirect to " + location
		}
		return false, false, true, body
	case status >= 400 && status < 500:
		return false, true, false, body
	default:
		return false, false, true, body
	}
}

// csrfAppRedirect reports whether a redirect Location stays on the
// application (same host as the form action, not a login/auth/error path).
func csrfAppRedirect(location, appHost string) bool {
	if location == "" {
		return false
	}
	if containsAnyToken(location, []string{"login", "signin", "sign-in", "auth", "error", "denied", "forbidden", "logout"}) {
		return false
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}
	// Relative locations always stay on the app.
	if parsed.Host == "" {
		return true
	}
	return parsed.Host == appHost
}

// csrfMissingSameSite inspects Set-Cookie values for session-like cookies
// lacking a SameSite attribute.
func csrfMissingSameSite(setCookies []string) (bool, string) {
	for _, sc := range setCookies {
		name := sc
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		lower := strings.ToLower(sc)
		if containsAnyToken(name, []string{"session", "sess", "sid", "auth", "token", "jwt"}) &&
			!strings.Contains(lower, "samesite") {
			return true, strings.TrimSpace(name)
		}
	}
	return false, ""
}

// postForm submits the form with (or without) its hidden token fields. Visible
// fields carry inert marker values so no guessed state changes are attempted.
func (m *CSRFTesting) postForm(ctx context.Context, form csrfForm, withToken bool) (int, string, string, []string, error) {
	values := url.Values{}
	for name := range form.VisibleFields {
		values.Set(name, csrfMarkerVal)
	}
	if withToken {
		for name, value := range form.HiddenFields {
			values.Set(name, value)
		}
	}

	resp, err := m.doRequest(ctx, "POST", form.Action, "application/x-www-form-urlencoded", values.Encode())
	if err != nil {
		return 0, "", "", nil, err
	}
	defer resp.Body.Close()

	bodyBytes, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		return resp.StatusCode, "", "", nil, readErr
	}

	setCookies := resp.Header.Values("Set-Cookie")
	return resp.StatusCode, string(bodyBytes), resp.Header.Get("Location"), setCookies, nil
}

// noteInconclusive appends an inconclusive row (deduplicated by detail).
// Callers must hold m.Mu.
func (m *CSRFTesting) noteInconclusive(detail string) {
	wrapped := formatEvidenceDetail(EvidenceWeak, detail)
	for _, r := range m.results {
		if r.Status == "inconclusive" && r.Detail == wrapped {
			return
		}
	}
	m.results = append(m.results, CSRFTestingResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceWeak, false),
		Detail: wrapped,
	})
}

func (m *CSRFTesting) testForm(ctx context.Context, form csrfForm, getBody string) {
	noTokStatus, noTokBody, noTokLoc, _, noTokErr := m.postForm(ctx, form, false)
	if noTokErr != nil {
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Token-less POST to %s failed: %v", form.Action, noTokErr))
		m.Mu.Unlock()
		return
	}
	withTokStatus, withTokBody, withTokLoc, withTokCookies, withTokErr := m.postForm(ctx, form, true)
	if withTokErr != nil {
		m.Mu.Lock()
		m.noteInconclusive(fmt.Sprintf("Token-bearing POST to %s failed: %v", form.Action, withTokErr))
		m.Mu.Unlock()
		return
	}

	appHost := ""
	if actionURL, err := url.Parse(form.Action); err == nil {
		appHost = actionURL.Host
	}

	noTokAccepted, noTokRejected, noTokUncertain, noTokEff := csrfClassifyResponse(noTokStatus, noTokBody, noTokLoc, appHost)
	withTokAccepted, withTokRejected, withTokUncertain, withTokEff := csrfClassifyResponse(withTokStatus, withTokBody, withTokLoc, appHost)

	m.Mu.Lock()
	defer m.Mu.Unlock()

	if missing, cookieName := csrfMissingSameSite(withTokCookies); missing {
		m.noteInconclusive(fmt.Sprintf("Session cookie %q was set without a SameSite attribute on POST response; CSRF defense in depth may be weakened.", cookieName))
	}

	switch {
	case noTokUncertain || withTokUncertain:
		m.noteInconclusive(fmt.Sprintf("POST responses to %s were indeterminate (token-less status %d, token-bearing status %d); CSRF acceptance could not be judged.",
			form.Action, noTokStatus, withTokStatus))

	case noTokRejected && withTokAccepted:
		// Token-less submission rejected while the token-bearing one is
		// accepted: the differential is the CSRF protection evidence.
		tier := EvaluateDifferentialEvidence(withTokEff, noTokEff, getBody, true)
		if tier == EvidenceConfirmed {
			m.results = append(m.results, CSRFTestingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, true),
				Detail: formatEvidenceDetail(EvidenceConfirmed, fmt.Sprintf("CSRF protection present at %s: token-less POST was rejected (HTTP %d) while the token-bearing POST was accepted (HTTP %d).",
					form.Action, noTokStatus, withTokStatus)),
			})
		} else {
			m.noteInconclusive(fmt.Sprintf("Token-less POST to %s was rejected while the token-bearing POST was accepted, but the differential could not be confirmed against the page baseline.",
				form.Action))
		}

	case noTokAccepted && withTokRejected:
		m.noteInconclusive(fmt.Sprintf("Token-bearing POST to %s was rejected while the token-less POST was accepted (HTTP %d/%d); response semantics are contradictory.",
			form.Action, noTokStatus, withTokStatus))

	case noTokAccepted && withTokAccepted:
		if len(form.HiddenFields) == 0 {
			// The form carries no CSRF token at all; a POST that diverges from
			// the GET baseline indicates an accepted state-changing request.
			tier := EvaluateDifferentialEvidence(noTokEff, getBody, getBody, true)
			if tier == EvidenceConfirmed && normalizedCompactLower(noTokEff) != normalizedCompactLower(getBody) {
				detail := fmt.Sprintf("POST form at %s was accepted without any CSRF token field and produced a response differing from the page baseline.", form.Action)
				m.RecordPoC(nil, nil, detail)
				m.results = append(m.results, CSRFTestingResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
				})
			} else {
				m.noteInconclusive(fmt.Sprintf("POST form at %s has no CSRF token field, but the response matched the GET baseline; no state change was observed.", form.Action))
			}
		} else {
			// Token field exists but the endpoint accepts submissions with and
			// without it. Only confirmed divergence (state change without the
			// token) is reportable; otherwise token enforcement is unclear.
			tier := EvaluateDifferentialEvidence(noTokEff, withTokEff, getBody, true)
			if tier == EvidenceConfirmed && normalizedCompactLower(noTokEff) != normalizedCompactLower(getBody) {
				detail := fmt.Sprintf("POST form at %s was accepted without its CSRF token and produced a response differing from the token-bearing baseline.", form.Action)
				m.RecordPoC(nil, nil, detail)
				m.results = append(m.results, CSRFTestingResult{
					Target: m.Target,
					Status: statusFromEvidence(EvidenceConfirmed, false),
					Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
				})
			} else {
				m.noteInconclusive(fmt.Sprintf("POST to %s was accepted both with and without the form token; token enforcement could not be confirmed.", form.Action))
			}
		}

	default: // both rejected
		m.noteInconclusive(fmt.Sprintf("Both the token-bearing and token-less POSTs to %s were rejected (HTTP %d/%d); validation or authentication prevented CSRF assessment.",
			form.Action, noTokStatus, withTokStatus))
	}
}

func init() {
	RegisterModule("csrf_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CSRFTesting on: %s", target))

		tester := NewCSRFTesting(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
