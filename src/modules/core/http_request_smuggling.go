package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HTTPRequestSmugglingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type HTTPRequestSmuggling struct {
	BaseModule
	Target  string
	results []HTTPRequestSmugglingResult
}

func NewHTTPRequestSmuggling(target string) *HTTPRequestSmuggling {
	return &HTTPRequestSmuggling{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *HTTPRequestSmuggling) Execute(ctx context.Context) ([]HTTPRequestSmugglingResult, error) {
	m.results = make([]HTTPRequestSmugglingResult, 0)

	endpoints := []string{"/"}

	var wg sync.WaitGroup
	jobs := make(chan string, len(endpoints))
	for _, ep := range endpoints {
		jobs <- ep
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testSmuggling(ctx, ep)
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *HTTPRequestSmuggling) testSmuggling(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint

	// Very rudimentary smuggle payload
	payload := "0\r\n\r\nGET / HTTP/1.1\r\nHost: " + m.Target + "\r\n\r\n"

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return
	}

	// Create conflicting headers
	req.Header.Add("Transfer-Encoding", "chunked")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(payload)))

	resp, err := m.Client.Do(req)
	if err != nil {
		// Timeouts could indicate a smuggling issue due to backend waiting
		if strings.Contains(err.Error(), "timeout") {
			m.Mu.Lock()
			m.RecordPoC(req, []byte(payload), fmt.Sprintf("Potential HTTP Request Smuggling (timeout) at: %s", testURL))
			m.results = append(m.results, HTTPRequestSmugglingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Potential request smuggling detected via timeout (TE.CL or CL.TE)",
			})
			m.Mu.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotImplemented {
		// Server probably rejected conflicting headers, not vulnerable to basic
		return
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 400 {
		return
	}

	if len(bodyBytes) > 0 {
		// A more complete smuggling test would require analyzing response offsets,
		// but for a heuristic check, we'll just flag if it didn't reject it immediately.
		m.Mu.Lock()
		m.RecordPoC(req, []byte(payload), fmt.Sprintf("Potential HTTP Request Smuggling (accepted) at: %s", testURL))
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Conflicting TE/CL headers were accepted",
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("http_request_smuggling_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting HTTPRequestSmuggling on: %s", target))
		tester := NewHTTPRequestSmuggling(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
