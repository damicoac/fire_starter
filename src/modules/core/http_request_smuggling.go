package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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

	// probeTimeout is the read deadline applied to raw probe/baseline exchanges.
	probeTimeout time.Duration
	// probeRepeats is how many times each desync probe must reproduce the
	// timing anomaly before the result is upgraded to "vulnerable".
	probeRepeats int
	// dial allows tests to inject raw connections; nil uses real TCP/TLS.
	dial func(ctx context.Context, addr string, useTLS bool) (net.Conn, error)
}

func NewHTTPRequestSmuggling(target string) *HTTPRequestSmuggling {
	return &HTTPRequestSmuggling{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target:       EnsureHTTPPrefix(target),
		probeTimeout: 5 * time.Second,
		probeRepeats: 2,
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

// defaultDial opens a raw TCP connection, upgrading to TLS with an
// HTTP/1.1-only ALPN selection: CL/TE desync probing is inapplicable over h2,
// so HTTP/2 must never be negotiated for these probes.
func (m *HTTPRequestSmuggling) defaultDial(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if useTLS {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		conn = tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
	}
	return conn, nil
}

// rawExchange writes a hand-crafted request over a raw TCP/TLS socket and
// reads the raw response. net/http's transport strips Content-Length and
// Transfer-Encoding from the header map, so desync probes can only be sent by
// writing raw request bytes. It reports whether a complete response arrived
// and whether the read timed out (potential desync hang).
func (m *HTTPRequestSmuggling) rawExchange(ctx context.Context, target *url.URL, rawReq []byte, timeout time.Duration) (complete bool, timedOut bool, err error) {
	useTLS := target.Scheme == "https"
	port := target.Port()
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(target.Hostname(), port)

	dial := m.dial
	if dial == nil {
		dial = m.defaultDial
	}
	conn, err := dial(ctx, addr, useTLS)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return false, false, err
	}
	if _, err := conn.Write(rawReq); err != nil {
		return false, false, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, false, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		if smuggleIsTimeoutErr(err) {
			return false, true, nil
		}
		return false, false, err
	}
	if resp.Body != nil {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			if smuggleIsTimeoutErr(err) {
				return false, true, nil
			}
			return false, false, err
		}
	}
	return true, false, nil
}

func smuggleIsTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return os.IsTimeout(err)
}

// smugglingRawRequest builds a raw HTTP/1.1 request with BOTH a
// Content-Length header and a Transfer-Encoding: chunked header followed by
// the ambiguous body, verbatim on the wire.
func smugglingRawRequest(target *url.URL, contentLength, body string) []byte {
	var b bytes.Buffer
	b.WriteString("POST " + target.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + target.Host + "\r\n")
	b.WriteString("Content-Length: " + contentLength + "\r\n")
	b.WriteString("Transfer-Encoding: chunked\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

// smugglingBaselineRequest builds an unambiguous Content-Length-only request
// used as the timing baseline. Sending Transfer-Encoding here would let a
// confused (or honest front-end) server hang the baseline itself.
func smugglingBaselineRequest(target *url.URL, contentLength, body string) []byte {
	var b bytes.Buffer
	b.WriteString("POST " + target.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + target.Host + "\r\n")
	b.WriteString("Content-Length: " + contentLength + "\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

func (m *HTTPRequestSmuggling) testSmuggling(ctx context.Context, endpoint string) {
	target, err := url.Parse(m.Target + endpoint)
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("Invalid target URL: %v", err),
		})
		m.Mu.Unlock()
		return
	}

	// 1. Baseline: plain, unambiguous Content-Length-only request must complete
	// quickly (no TE header, so an honest server cannot be made to hang it).
	baselineReq := smugglingBaselineRequest(target, "8", "baseline")
	complete, timedOut, err := m.rawExchange(ctx, target, baselineReq, m.probeTimeout)
	if err != nil {
		m.Mu.Lock()
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("Baseline request failed: %v", err),
		})
		m.Mu.Unlock()
		return
	}
	if timedOut || !complete {
		m.Mu.Lock()
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "Baseline request did not complete; target is too slow or unreachable for reliable timing analysis.",
		})
		m.Mu.Unlock()
		return
	}

	// 2. CL.TE desync timing check.
	if m.runDesyncProbe(ctx, target, "4", "1\r\nA\r\nX", "CL.TE") {
		return
	}

	// 3. TE.CL desync timing check.
	m.runDesyncProbe(ctx, target, "6", "0\r\n\r\nX", "TE.CL")
}

// runDesyncProbe sends the ambiguous CL+TE body probeRepeats times. A finding
// requires the hang to reproduce on every probe with a fast baseline; a lone
// timeout is reported inconclusive instead of vulnerable.
func (m *HTTPRequestSmuggling) runDesyncProbe(ctx context.Context, target *url.URL, contentLength, body, variant string) bool {
	repeats := m.probeRepeats
	if repeats < 2 {
		repeats = 2
	}
	timeouts := 0
	errs := 0
	var lastErr error
	for i := 0; i < repeats; i++ {
		raw := smugglingRawRequest(target, contentLength, body)
		complete, timedOut, err := m.rawExchange(ctx, target, raw, m.probeTimeout)
		switch {
		case err != nil:
			errs++
			lastErr = err
		case timedOut || !complete:
			timeouts++
		}
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	switch {
	case timeouts == repeats:
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("Vulnerable to %s request smuggling (reproducible timing desync across %d probes)", variant, repeats),
		})
		return true
	case timeouts > 0:
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("Possible %s desync: probe timed out on %d of %d attempts; not reproducible enough to confirm.", variant, timeouts, repeats),
		})
	case errs == repeats:
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("%s probe failed on every attempt: %v", variant, lastErr),
		})
	case errs > 0:
		// Partial probe errors: the variant could not be evaluated reliably.
		m.results = append(m.results, HTTPRequestSmugglingResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: fmt.Sprintf("%s probe errored on %d of %d attempts (last error: %v); desync status unknown.", variant, errs, repeats, lastErr),
		})
	}
	return false
}

func init() {
	RegisterModule("http_request_smuggling_testing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "")
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
