package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []ErrorMessageAnalysisResult
	client     *http.Client
}

// NewErrorMessageAnalysis creates a new instance of ErrorMessageAnalysis.
func NewErrorMessageAnalysis(target string) *ErrorMessageAnalysis {
	return &ErrorMessageAnalysis{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *ErrorMessageAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
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

	for i := 0; i < m.maxThreads; i++ {
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
					
					resp, err := m.client.Do(req)
					if err != nil {
						continue
					}
					defer resp.Body.Close()

					bodyBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						continue
					}
					bodyStr := string(bodyBytes)

					for sigName, sigText := range errorSignatures {
						if strings.Contains(bodyStr, sigText) {
							m.mu.Lock()
							m.results = append(m.results, ErrorMessageAnalysisResult{
								Target: m.Target,
								Status: "vulnerable",
								Detail: "Leaked " + sigName + " on " + targetURL,
							})
							m.mu.Unlock()
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
