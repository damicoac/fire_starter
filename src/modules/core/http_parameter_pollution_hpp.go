package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HttpParameterPollutionHppResult holds the result of the HttpParameterPollutionHpp module execution.
type HttpParameterPollutionHppResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HttpParameterPollutionHpp executes the http_parameter_pollution_hpp security technique.
type HttpParameterPollutionHpp struct {
	BaseModule
	Target  string
	results []HttpParameterPollutionHppResult
	// Count of probes that failed on transport/build/body-read errors.
	probeErrs []string
}

// hppPollutedValue is the benign marker appended for the polluted probe.
const hppPollutedValue = "polluted_value_12345"

// NewHttpParameterPollutionHpp creates a new instance.
func NewHttpParameterPollutionHpp(target string) *HttpParameterPollutionHpp {
	return &HttpParameterPollutionHpp{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *HttpParameterPollutionHpp) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *HttpParameterPollutionHpp) Execute(ctx context.Context) ([]HttpParameterPollutionHppResult, error) {
	m.Mu.Lock()
	m.results = make([]HttpParameterPollutionHppResult, 0)
	m.probeErrs = nil
	m.Mu.Unlock()

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	// For HPP, we need to find parameters. If none exist, we guess some.
	query := parsedURL.Query()
	if len(query) == 0 {
		query.Add("user", "1")
		query.Add("id", "1")
	}

	jobs := make(chan string, len(query))
	for key := range query {
		jobs <- key
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for param := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testParameter(ctx, parsedURL, query, param)
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
		m.Mu.Lock()
		if len(m.results) == 0 && len(m.probeErrs) > 0 {
			m.results = append(m.results, HttpParameterPollutionHppResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, fmt.Sprintf("All probes failed; first error: %s", m.probeErrs[0])),
			})
		}
		m.Mu.Unlock()
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *HttpParameterPollutionHpp) recordProbeError(err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.probeErrs) < 8 {
		m.probeErrs = append(m.probeErrs, err.Error())
	}
}

// hppFetch executes a GET with the given query and returns status/body.
func (m *HttpParameterPollutionHpp) hppFetch(ctx context.Context, u *url.URL, rawQuery string) (int, string, error) {
	testURL := *u
	testURL.RawQuery = rawQuery

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return 0, "", fmt.Errorf("failed to build HPP request: %w", err)
	}

	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("HPP probe request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _, readErr := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		return resp.StatusCode, "", fmt.Errorf("failed to read HPP response body: %w", readErr)
	}

	return resp.StatusCode, string(bodyBytes), nil
}

func (m *HttpParameterPollutionHpp) testParameter(ctx context.Context, u *url.URL, originalQuery url.Values, paramToPollute string) {
	// Original query (baseline): keep the parameter exactly as discovered.
	qBaseline := url.Values{}
	for k, v := range originalQuery {
		qBaseline[k] = v
	}
	rawBaseline := qBaseline.Encode()

	// Control: the target parameter alone set to a benign value; other params
	// kept. Distinguishes "server chokes on garbage input" from true HPP.
	qControl := url.Values{}
	for k, v := range originalQuery {
		qControl[k] = v
	}
	if len(originalQuery[paramToPollute]) > 0 {
		qControl[paramToPollute] = []string{hppPollutedValue}
	} else {
		qControl.Del(paramToPollute)
		qControl.Add(paramToPollute, hppPollutedValue)
	}
	rawControl := qControl.Encode()

	// Polluted pair: the original value plus our payload for the target
	// parameter, all other parameters preserved.
	qPolluted := url.Values{}
	for k, v := range originalQuery {
		qPolluted[k] = v
	}
	originalVal := originalQuery.Get(paramToPollute)
	if len(originalQuery[paramToPollute]) > 0 {
		qPolluted[paramToPollute] = []string{originalVal, hppPollutedValue}
	} else {
		qPolluted.Del(paramToPollute)
		qPolluted.Add(paramToPollute, hppPollutedValue)
	}
	rawPolluted := qPolluted.Encode()

	m.Mu.Lock()
	m.Mu.Unlock()

	baselineStatus, _, err := m.hppFetch(ctx, u, rawBaseline)
	if err != nil {
		m.recordProbeError(err)
		return
	}
	controlStatus, controlBody, err := m.hppFetch(ctx, u, rawControl)
	if err != nil {
		m.recordProbeError(err)
		return
	}
	pollutedStatus, pollutedBody, err := m.hppFetch(ctx, u, rawPolluted)
	if err != nil {
		m.recordProbeError(err)
		return
	}

	// Any 500 on its own is NOT proof of HPP: int-typed params 500 on garbage
	// input and some endpoints 500 on everything. A 500 is only meaningful when
	// the polluted pair behaves differently from the baseline AND the control.
	// Otherwise judge by the concatenated-value differential.
	vulnerable := false
	if pollutedStatus == http.StatusInternalServerError &&
		baselineStatus != http.StatusInternalServerError &&
		controlStatus != http.StatusInternalServerError {
		// Polluted pair specifically breaks the request while the same payload
		// alone does not: a duplicate-parameter parsing difference.
		vulnerable = true
	} else if pollutedStatus == baselineStatus && pollutedStatus == controlStatus {
		// Same status: look for server-side concatenation of both values in the
		// response body (ASP.NET style), in either order, where the control
		// response does not contain the pair.
		if hppConcatenationEvidence(pollutedBody, originalVal, hppPollutedValue) &&
			!hppConcatenationEvidence(controlBody, originalVal, hppPollutedValue) {
			vulnerable = true
		}
	}

	if vulnerable {
		detail := "HTTP Parameter Pollution detected on parameter: " + paramToPollute
		req, _ := http.NewRequestWithContext(ctx, "GET", (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawQuery: rawPolluted}).String(), nil)
		m.Mu.Lock()
		m.RecordPoC(req, nil, detail)
		m.results = append(m.results, HttpParameterPollutionHppResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
		})
		m.Mu.Unlock()
	}
}

// hppConcatenationEvidence reports whether the body contains both values
// joined (original+polluted or polluted+original) with a separator.
func hppConcatenationEvidence(body, originalVal, pollutedVal string) bool {
	if originalVal == "" || pollutedVal == "" {
		return false
	}
	// Compare against the baseline body so dynamic pages do not produce
	// coincidental matches; body here is the polluted-response body.
	for _, sep := range []string{",", ";", " ", "|", ""} {
		if strings.Contains(body, originalVal+sep+pollutedVal) ||
			strings.Contains(body, pollutedVal+sep+originalVal) {
			return true
		}
	}
	return false
}

func init() {
	RegisterModule("http_parameter_pollution_hpp", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting HttpParameterPollutionHpp on: %s", target))

		tester := NewHttpParameterPollutionHpp(target)
		tester.SetThreads(PayloadInt(payload, "threads", 5))

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
