package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CorsMisconfigurationAnalysisResult holds the result of the CorsMisconfigurationAnalysis module execution.
type CorsMisconfigurationAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CorsMisconfigurationAnalysis executes the cors_misconfiguration_analysis security technique.
type CorsMisconfigurationAnalysis struct {
	BaseModule
	Target  string
	results []CorsMisconfigurationAnalysisResult

	// per-run probe bookkeeping (guarded by m.Mu)
	probeCount            int
	probeFailures         int
	probeFailMsg          string
	getFailureReported    bool
	wildcardCredsReported bool
}

// NewCorsMisconfigurationAnalysis creates a new instance.
func NewCorsMisconfigurationAnalysis(target string) *CorsMisconfigurationAnalysis {
	return &CorsMisconfigurationAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *CorsMisconfigurationAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *CorsMisconfigurationAnalysis) Execute(ctx context.Context) ([]CorsMisconfigurationAnalysisResult, error) {
	m.results = make([]CorsMisconfigurationAnalysisResult, 0)
	m.Mu.Lock()
	m.probeCount = 0
	m.probeFailures = 0
	m.probeFailMsg = ""
	m.getFailureReported = false
	m.wildcardCredsReported = false
	m.Mu.Unlock()

	originsToTest := []string{
		"https://evil.com",
		"http://evil.com",
		"null",
	}

	host := ExtractTargetHost(m.Target)
	if host != "" {
		originsToTest = append(originsToTest, "https://subdomain."+host+".evil.com", "https://nottrusted."+host)
	} else {
		originsToTest = append(originsToTest, "https://subdomain.target.com.evil.com")
	}

	jobs := make(chan string, len(originsToTest))
	for _, o := range originsToTest {
		jobs <- o
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for origin := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testOrigin(ctx, origin)
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
		m.summarize()
		res := make([]CorsMisconfigurationAnalysisResult, len(m.results))
		copy(res, m.results)
		m.Mu.Unlock()
		return res, nil
	case <-ctx.Done():
		<-done
		m.Mu.Lock()
		m.summarize()
		res := make([]CorsMisconfigurationAnalysisResult, len(m.results))
		copy(res, m.results)
		m.Mu.Unlock()
		return res, ctx.Err()
	}
}

// summarize appends a closing row so an unreachable target is never reported
// as a fabricated negative ("safe"). Callers must hold m.Mu.
func (m *CorsMisconfigurationAnalysis) summarize() {
	if len(m.results) > 0 {
		return
	}
	if m.probeCount == 0 || m.probeFailures >= m.probeCount {
		detail := "All origin probes failed; CORS configuration could not be evaluated."
		if m.probeFailMsg != "" {
			detail += " Last error: " + m.probeFailMsg
		}
		m.results = append(m.results, CorsMisconfigurationAnalysisResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: detail,
		})
		return
	}
	if m.probeFailures > 0 {
		// Some probes failed: "all origins rejected" cannot be confirmed.
		detail := "Some origin probes failed; CORS configuration could not be fully evaluated."
		if m.probeFailMsg != "" {
			detail += " Last error: " + m.probeFailMsg
		}
		m.results = append(m.results, CorsMisconfigurationAnalysisResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: detail,
		})
		return
	}
	m.results = append(m.results, CorsMisconfigurationAnalysisResult{
		Target: m.Target,
		Status: "secure",
		Detail: "All tested malicious origins were rejected.",
	})
}

func (m *CorsMisconfigurationAnalysis) testOrigin(ctx context.Context, origin string) {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", m.Target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeFailures++
		if m.probeFailMsg == "" {
			m.probeFailMsg = err.Error()
		}
		m.Mu.Unlock()
		return
	}

	m.Mu.Lock()
	m.probeCount++
	m.Mu.Unlock()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
	resp.Body.Close()

	reflected := allowOrigin == origin || allowOrigin == "*"
	if !reflected {
		return
	}

	// Preflight reflection alone is not exploitable: confirm the same origin is
	// allowed on the actual cross-origin GET before calling this vulnerable.
	getReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return
	}
	getReq.Header.Set("Origin", origin)
	getResp, err := m.Client.Do(getReq)
	if err != nil {
		m.Mu.Lock()
		m.probeFailures++
		if m.probeFailMsg == "" {
			m.probeFailMsg = err.Error()
		}
		// The reflecting preflight could not be confirmed on the actual GET:
		// record one inconclusive row for the run instead of silently dropping
		// the signal.
		if !m.getFailureReported {
			m.getFailureReported = true
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: "Origin reflection observed on the OPTIONS preflight, but the confirming cross-origin GET failed; CORS status could not be verified. Last error: " + err.Error(),
			})
		}
		m.Mu.Unlock()
		return
	}
	defer getResp.Body.Close()

	getAllowOrigin := getResp.Header.Get("Access-Control-Allow-Origin")
	if getAllowOrigin != allowOrigin {
		// Server reflects on preflight only; the GET the browser actually
		// issues is not allowed, so no readable cross-origin access exists.
		return
	}

	switch {
	case allowOrigin == "*":
		if allowCreds == "true" {
			// Browsers refuse to send credentials with a wildcard origin:
			// not exploitable for credentialed reads. Report once per run.
			m.Mu.Lock()
			if !m.wildcardCredsReported {
				m.wildcardCredsReported = true
				m.results = append(m.results, CorsMisconfigurationAnalysisResult{
					Target: m.Target,
					Status: "inconclusive",
					Detail: "Access-Control-Allow-Origin '*' with Access-Control-Allow-Credentials: true; browsers reject credentials for wildcard origins so this is not exploitable for credentialed reads.",
				})
			}
			m.Mu.Unlock()
		}
	case allowOrigin == "null":
		m.Mu.Lock()
		m.RecordPoC(req, nil, "CORS misconfiguration: Allows 'null' Origin")
		m.results = append(m.results, CorsMisconfigurationAnalysisResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "CORS misconfiguration: Allows 'null' Origin",
		})
		m.Mu.Unlock()
	default:
		// Credentialed access requires an exact reflected origin (not '*').
		if allowCreds == "true" {
			m.Mu.Lock()
			m.RecordPoC(req, nil, "CORS misconfiguration: Allows Origin '"+origin+"' with Credentials")
			m.results = append(m.results, CorsMisconfigurationAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "CORS misconfiguration: Allows Origin '" + origin + "' with Credentials",
			})
			m.Mu.Unlock()
		}
	}
}

func init() {
	RegisterModule("cors_misconfiguration_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting CorsMisconfigurationAnalysis on: %s", target))

		tester := NewCorsMisconfigurationAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
