package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type customTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.roundTrip(req)
}

// fakeSmuggleConn is a net.Conn stub for the raw-socket smuggling probes.
type fakeSmuggleConn struct {
	mu           sync.Mutex
	written      bytes.Buffer
	resp         string // raw response bytes returned on first read
	respSent     bool
	timeoutReads bool // every read blocks until the deadline, then fails
	deadline     time.Time
}

func (c *fakeSmuggleConn) Read(p []byte) (int, error) {
	if c.timeoutReads {
		d := time.Until(c.deadline)
		if d > 0 {
			time.Sleep(d)
		}
		return 0, os.ErrDeadlineExceeded
	}
	if c.respSent {
		return 0, io.EOF
	}
	c.respSent = true
	return copy(p, c.resp), nil
}

func (c *fakeSmuggleConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written.Write(p)
	return len(p), nil
}

func (c *fakeSmuggleConn) Close() error                       { return nil }
func (c *fakeSmuggleConn) LocalAddr() net.Addr                { return nil }
func (c *fakeSmuggleConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeSmuggleConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeSmuggleConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *fakeSmuggleConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

const smuggleOKResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

func TestHTTPRequestSmuggling_WireBytesContainCLAndTE(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var probeBytes []byte
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				total := 0
				for total < len(buf) {
					c.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, rerr := c.Read(buf[total:])
					total += n
					if rerr != nil {
						break
					}
					if bytes.Contains(buf[:total], []byte("\r\n\r\n")) {
						// grace read for the (ambiguous) body
						c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					}
				}
				if bytes.Contains(buf[:total], []byte("Content-Length:")) &&
					bytes.Contains(buf[:total], []byte("Transfer-Encoding: chunked")) {
					chunk := make([]byte, total)
					copy(chunk, buf[:total])
					mu.Lock()
					probeBytes = chunk
					mu.Unlock()
				}
				c.Write([]byte(smuggleOKResponse))
			}(conn)
		}
	}()

	module := NewHTTPRequestSmuggling("http://" + ln.Addr().String())
	module.probeTimeout = 2 * time.Second
	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("Expected no findings against a server that answers normally, got: %+v", result)
	}

	mu.Lock()
	captured := probeBytes
	mu.Unlock()
	if captured == nil {
		t.Fatalf("Expected probe requests to carry both Content-Length and Transfer-Encoding on the wire")
	}
	if !bytes.Contains(captured, []byte("Content-Length:")) || !bytes.Contains(captured, []byte("Transfer-Encoding: chunked")) {
		t.Fatalf("Wire bytes missing CL/TE headers: %q", captured)
	}
}

// smuggleDialMock returns a dial func whose connections respond with the
// given raw response, except: connections with call number >= timeoutFromCall
// (when timeoutAll) or exactly timeoutCall time out. Call 1 is the baseline.
func smuggleDialMock(response string, timeoutAll bool, timeoutFromCall, timeoutCall int) func(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
	var calls int32
	return func(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
		n := int(atomic.AddInt32(&calls, 1))
		if (timeoutAll && n >= timeoutFromCall) || n == timeoutCall {
			return &fakeSmuggleConn{timeoutReads: true}, nil
		}
		return &fakeSmuggleConn{resp: response}, nil
	}
}

func TestHTTPRequestSmuggling_Execute_ReproducibleTimeout_Vulnerable(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	module.probeTimeout = 300 * time.Millisecond
	// Baseline answers normally; both CL.TE probe repeats hang.
	module.dial = smuggleDialMock(smuggleOKResponse, true, 2, -1)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected exactly one vulnerable row, got: %+v", result)
	}
	if result[0].Status != "vulnerable" || !strings.Contains(result[0].Detail, "CL.TE") {
		t.Fatalf("Unexpected result: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_SingleTimeout_Inconclusive(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	module.probeTimeout = 300 * time.Millisecond
	// call 2 is the first CL.TE probe: it times out, the repeat responds.
	module.dial = smuggleDialMock(smuggleOKResponse, false, 0, 2)

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected exactly one row, got: %+v", result)
	}
	if result[0].Status != "inconclusive" || !strings.Contains(result[0].Detail, "CL.TE") {
		t.Fatalf("Expected inconclusive for non-reproducible desync, got: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_BaselineTimeout_Inconclusive(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	module.probeTimeout = 300 * time.Millisecond
	module.dial = func(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
		return &fakeSmuggleConn{timeoutReads: true}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive row on baseline timeout, got: %+v", result)
	}
	if result[0].Status != "inconclusive" || !strings.Contains(result[0].Detail, "Baseline") {
		t.Fatalf("Expected inconclusive baseline row, got: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_PartialProbeErrors_Inconclusive(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	module.probeTimeout = 300 * time.Millisecond
	var calls int32
	module.dial = func(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
		n := int(atomic.AddInt32(&calls, 1))
		if n == 2 {
			// First CL.TE probe connection fails; the repeat and every other
			// exchange succeed, so the desync status is unknown.
			return nil, errors.New("connection refused")
		}
		return &fakeSmuggleConn{resp: smuggleOKResponse}, nil
	}

	result, err := module.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected exactly one inconclusive row for partial probe errors, got: %+v", result)
	}
	if result[0].Status != "inconclusive" || !strings.Contains(result[0].Detail, "CL.TE") {
		t.Fatalf("Expected inconclusive partial-error row for CL.TE, got: %+v", result[0])
	}
}

func TestHTTPRequestSmuggling_Execute_CanceledContext(t *testing.T) {
	module := NewHTTPRequestSmuggling("http://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = module.Execute(ctx)
}
