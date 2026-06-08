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

	// 1. Baseline Request
	baselineReq, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString("baseline"))
	if err != nil {
		return
	}
	baselineResp, err := m.Client.Do(baselineReq)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "context deadline exceeded") {
			// Baseline times out, target is naturally slow, skip to avoid false positives
			return
		}
	} else {
		io.Copy(io.Discard, baselineResp.Body)
		baselineResp.Body.Close()
	}

	// 2. CL.TE Timing Check
	cltePayload := "1\r\nA\r\nX"
	clteReq, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(cltePayload))
	if err == nil {
		clteReq.Header.Add("Transfer-Encoding", "chunked")
		clteReq.Header.Add("Content-Length", "4")
		
		clteResp, err := m.Client.Do(clteReq)
		if err != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "context deadline exceeded")) {
			m.Mu.Lock()
			m.RecordPoC(clteReq, []byte(cltePayload), fmt.Sprintf("CL.TE HTTP Request Smuggling timeout at: %s", testURL))
			m.results = append(m.results, HTTPRequestSmugglingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Vulnerable to CL.TE request smuggling (timing based)",
			})
			m.Mu.Unlock()
			return // already found vulnerability
		} else if err == nil {
			io.Copy(io.Discard, clteResp.Body)
			clteResp.Body.Close()
		}
	}

	// 3. TE.CL Timing Check
	teclPayload := "0\r\n\r\nX"
	teclReq, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(teclPayload))
	if err == nil {
		teclReq.Header.Add("Transfer-Encoding", "chunked")
		teclReq.Header.Add("Content-Length", "6")

		teclResp, err := m.Client.Do(teclReq)
		if err != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "context deadline exceeded")) {
			m.Mu.Lock()
			m.RecordPoC(teclReq, []byte(teclPayload), fmt.Sprintf("TE.CL HTTP Request Smuggling timeout at: %s", testURL))
			m.results = append(m.results, HTTPRequestSmugglingResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Vulnerable to TE.CL request smuggling (timing based)",
			})
			m.Mu.Unlock()
		} else if err == nil {
			io.Copy(io.Discard, teclResp.Body)
			teclResp.Body.Close()
		}
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
