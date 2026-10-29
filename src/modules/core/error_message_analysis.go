package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrorMessageAnalysisResult holds the result of the ErrorMessageAnalysis module execution.
type ErrorMessageAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ErrorMessageAnalysis executes the error_message_analysis security technique.
type ErrorMessageAnalysis struct {
	BaseModule
	Target  string
	results []ErrorMessageAnalysisResult
}

// NewErrorMessageAnalysis creates a new instance of ErrorMessageAnalysis.
func NewErrorMessageAnalysis(target string) *ErrorMessageAnalysis {
	return &ErrorMessageAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *ErrorMessageAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var errorSignatures = map[string]string{
	"Tomcat Error":     "Apache Tomcat/",
	"Django Error":     "Django Version:",
	"Flask Error":      "werkzeug.exceptions",
	"Rails Error":      "Ruby on Rails application could not be started",
	"PHP Error":        "Fatal error</b>:",
	"ASP.NET Error":    "Server Error in '/' Application.",
	"Express Error":    "SyntaxError: Unexpected",
	"Spring Error":     "Whitelabel Error Page",
	"ColdFusion Error": "ColdFusion.sql.exception",
}

func (m *ErrorMessageAnalysis) Execute(ctx context.Context) ([]ErrorMessageAnalysisResult, error) {
	m.Mu.Lock()
	m.results = make([]ErrorMessageAnalysisResult, 0)
	m.Mu.Unlock()

	// Baseline fetch: signatures already present on the normal page are not
	// attributable to the error probes.
	baselineStatus, baselineBody, baselineErr := m.fetch(ctx, m.Target)
	if baselineErr != nil {
		m.Mu.Lock()
		m.results = append(m.results, ErrorMessageAnalysisResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline request failed: "+baselineErr.Error()),
		})
		m.Mu.Unlock()
		return m.results, nil
	}

	// Create bad payloads to append to path
	payloads := []string{
		"'", "%00", "/%2e%2e%2f", "/.git/config", "/invalid-url-12345",
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(payloads))

	for _, p := range payloads {
		jobs <- p
	}
	close(jobs)

	var probeFailures int
	var failuresMu sync.Mutex
	seenSignatures := make(map[string]bool) // per-run dedupe, guarded by m.Mu

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					targetURL := strings.TrimRight(m.Target, "/") + payload
					status, bodyStr, err := m.fetch(ctx, targetURL)
					if err != nil {
						// Request-build failures (e.g. malformed payloads like
						// %00) are skipped; only transport failures count.
						if !isRequestBuildError(err) {
							failuresMu.Lock()
							probeFailures++
							failuresMu.Unlock()
						}
						continue
					}

					m.Mu.Lock()
					for sigName, sigText := range errorSignatures {
						if !strings.Contains(bodyStr, sigText) {
							continue
						}
						if seenSignatures[sigName] {
							continue
						}
						// Gate: the signature must surface on an error status
						// (and the baseline must not already be an error
						// page), or on a 2xx page that differs from the
						// baseline without already containing the signature.
						eligible := status >= 400 && baselineStatus < 400
						if !eligible && status >= 200 && status < 300 {
							eligible = bodyStr != baselineBody && !strings.Contains(baselineBody, sigText)
						}
						if !eligible {
							continue
						}
						seenSignatures[sigName] = true
						detail := fmt.Sprintf("Leaked %s on %s (HTTP %d)", sigName, targetURL, status)
						m.RecordPoC(nil, nil, detail)
						m.results = append(m.results, ErrorMessageAnalysisResult{
							Target: m.Target,
							Status: statusFromEvidence(EvidenceConfirmed, false),
							Detail: formatEvidenceDetail(EvidenceConfirmed, detail),
						})
					}
					m.Mu.Unlock()
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
		if probeFailures > 0 {
			m.Mu.Lock()
			m.noteInconclusive(fmt.Sprintf("%d of %d error-message probes failed with transport errors; target reachability could not be fully established.",
				probeFailures, len(payloads)))
			m.Mu.Unlock()
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

// isRequestBuildError reports whether err stems from request construction
// (e.g. a malformed payload URL) rather than a transport failure.
func isRequestBuildError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Op == "parse"
	}
	return false
}

// fetch performs a GET and returns (status, body, error).
func (m *ErrorMessageAnalysis) fetch(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	if cookies := m.BaseModule.GetCookies(); cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(bodyBytes), nil
}

// noteInconclusive appends a deduplicated inconclusive row. Callers must hold m.Mu.
func (m *ErrorMessageAnalysis) noteInconclusive(detail string) {
	wrapped := formatEvidenceDetail(EvidenceWeak, detail)
	for _, r := range m.results {
		if r.Status == "inconclusive" && r.Detail == wrapped {
			return
		}
	}
	m.results = append(m.results, ErrorMessageAnalysisResult{
		Target: m.Target,
		Status: statusFromEvidence(EvidenceWeak, false),
		Detail: wrapped,
	})
}

func init() {
	RegisterModule("error_message_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting ErrorMessageAnalysis on: %s", target))

		tester := NewErrorMessageAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
