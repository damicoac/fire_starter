package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	"PHP Error":        "Fatal error:</b>",
	"ASP.NET Error":    "Server Error in '/' Application.",
	"Express Error":    "SyntaxError: Unexpected",
	"Spring Error":     "Whitelabel Error Page",
	"ColdFusion Error": "ColdFusion.sql.exception",
}

func (m *ErrorMessageAnalysis) Execute(ctx context.Context) ([]ErrorMessageAnalysisResult, error) {
	m.results = make([]ErrorMessageAnalysisResult, 0)

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

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					targetURL := strings.TrimRight(m.Target, "/") + payload
					req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
					if err != nil {
						continue
					}

					resp, err := m.Client.Do(req)
					if err != nil {
						continue
					}

					bodyBytes, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)

					for sigName, sigText := range errorSignatures {
						if strings.Contains(bodyStr, sigText) {
							m.Mu.Lock()
							m.RecordPoC(req, nil, "Leaked "+sigName+" on "+targetURL)
							m.results = append(m.results, ErrorMessageAnalysisResult{
								Target: m.Target,
								Status: "vulnerable",
								Detail: "Leaked " + sigName + " on " + targetURL,
							})
							m.Mu.Unlock()
						}
					}
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
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
