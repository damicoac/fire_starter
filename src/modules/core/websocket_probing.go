package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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

	// http11Client is a dedicated HTTP/1.1-only client: HTTP/2 transports
	// reject the Connection/Upgrade headers a WebSocket handshake requires,
	// which made https targets silently unprobeable.
	http11Client *http.Client

	// per-run probe bookkeeping (guarded by m.Mu)
	probeCount    int
	probeErrCount int
}

func NewWebSocketProbing(target string) *WebSocketProbing {
	m := &WebSocketProbing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
	m.http11Client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: http11Transport(),
	}
	return m
}

// http11Transport clones the package default transport and forces HTTP/1.1
// so Upgrade/Connection headers reach the server. If the default transport
// has been replaced (e.g. by a test mock) it is used as-is.
func http11Transport() http.RoundTripper {
	if t, ok := getDefaultTransport().(*http.Transport); ok {
		tr := t.Clone()
		tr.ForceAttemptHTTP2 = false
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		return tr
	}
	return getDefaultTransport()
}

func (m *WebSocketProbing) Execute(ctx context.Context) ([]WebSocketProbingResult, error) {
	m.results = make([]WebSocketProbingResult, 0)
	m.Mu.Lock()
	m.probeCount = 0
	m.probeErrCount = 0
	m.Mu.Unlock()

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

	// Never end silently-empty: summarize the run outcome.
	m.Mu.Lock()
	if len(m.results) == 0 && ctx.Err() == nil {
		if m.probeErrCount > 0 {
			m.results = append(m.results, WebSocketProbingResult{
				Target: m.Target,
				Status: "inconclusive",
				Detail: fmt.Sprintf("%d of %d WebSocket probes failed; endpoints could not be fully evaluated.", m.probeErrCount, m.probeCount),
			})
		} else if m.probeCount > 0 {
			m.results = append(m.results, WebSocketProbingResult{
				Target: m.Target,
				Status: "secure",
				Detail: "All WebSocket endpoints rejected the spoofed-Origin handshake.",
			})
		}
	}
	res := make([]WebSocketProbingResult, len(m.results))
	copy(res, m.results)
	m.Mu.Unlock()
	return res, ctx.Err()
}

// wsUpgradeRequest issues a WebSocket handshake request over the HTTP/1.1-only
// client. An empty origin omits the Origin header (control probe).
func (m *WebSocketProbing) wsUpgradeRequest(ctx context.Context, httpURL, origin string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return m.http11Client.Do(req)
}

func (m *WebSocketProbing) testWebSocket(ctx context.Context, endpoint string) {
	httpURL := m.Target + endpoint

	m.Mu.Lock()
	m.probeCount++
	m.Mu.Unlock()

	probeResp, err := m.wsUpgradeRequest(ctx, httpURL, "http://evil.com")
	if err != nil {
		m.Mu.Lock()
		m.probeErrCount++
		m.Mu.Unlock()
		return
	}
	defer probeResp.Body.Close()

	if probeResp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	// Control probe without an Origin header: public anonymous endpoints
	// return 101 for any Origin. The module holds no session cookies, so a
	// 101 without origin validation cannot establish CSWSH impact.
	controlResp, err := m.wsUpgradeRequest(ctx, httpURL, "")
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, WebSocketProbingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("WebSocket endpoint accepted spoofed Origin at %s, but the no-Origin control request failed: %v", httpURL, err),
		})
		m.Mu.Unlock()
		return
	}
	defer controlResp.Body.Close()

	if controlResp.StatusCode == http.StatusSwitchingProtocols {
		m.Mu.Lock()
		m.results = append(m.results, WebSocketProbingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("WebSocket endpoint at %s accepts upgrades regardless of Origin; module holds no session credentials, so cross-Site WebSocket Hijacking impact could not be confirmed.", httpURL),
		})
		m.Mu.Unlock()
		return
	}

	m.Mu.Lock()
	m.RecordPoC(probeResp.Request, nil, fmt.Sprintf("CSWSH Vulnerability (Accepts spoofed Origin, rejects no-Origin control) at: %s", httpURL))
	m.results = append(m.results, WebSocketProbingResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: fmt.Sprintf("WebSocket endpoint accepted connection with spoofed Origin while rejecting the no-Origin control: %s", httpURL),
	})
	m.Mu.Unlock()
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
