package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type WebSocketProbingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type WebSocketProbing struct {
	BaseModule
	Target  string
	results []WebSocketProbingResult
}

func NewWebSocketProbing(target string) *WebSocketProbing {
	return &WebSocketProbing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *WebSocketProbing) Execute(ctx context.Context) ([]WebSocketProbingResult, error) {
	m.results = make([]WebSocketProbingResult, 0)

	endpoints := []string{
		"/ws",
		"/socket.io/",
		"/chat",
		"/stream",
	}

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
					m.testWebSocket(ctx, ep)
				}
			}
		}()
	}

	wg.Wait()
	return m.results, nil
}

func (m *WebSocketProbing) testWebSocket(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint
	if strings.HasPrefix(testURL, "https://") {
		testURL = strings.Replace(testURL, "https://", "wss://", 1)
	} else if strings.HasPrefix(testURL, "http://") {
		testURL = strings.Replace(testURL, "http://", "ws://", 1)
	}

	// This is a heuristic test, we just check if it accepts websocket connections
	// without origin validation by attempting a standard HTTP upgrade request
	// with a spoofed origin.
	httpURL := m.Target + endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "http://evil.com") // Spoofed origin

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		m.Mu.Lock()
		m.RecordPoC(req, nil, fmt.Sprintf("CSWSH Vulnerability (Accepts any Origin) at: %s", httpURL))
		m.results = append(m.results, WebSocketProbingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("WebSocket endpoint accepted connection with spoofed Origin: %s", httpURL),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("websocket_vulnerability_probing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting WebSocketProbing on: %s", target))
		tester := NewWebSocketProbing(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
