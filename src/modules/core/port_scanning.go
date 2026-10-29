package core

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// PortScanningResult holds the result of the PortScanning module execution.
type PortScanningResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PortScanning executes the port_scanning security technique.
type PortScanning struct {
	BaseModule
	Target  string
	results []PortScanningResult
	// scan is an optional test hook replacing the default PortScanner run.
	scan func(ctx context.Context) ([]portResult, error)
}

// NewPortScanning creates a new instance.
func NewPortScanning(target string) *PortScanning {
	return &PortScanning{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target,
	}
}

func (m *PortScanning) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *PortScanning) Execute(ctx context.Context) ([]PortScanningResult, error) {
	m.results = make([]PortScanningResult, 0)

	targetHost := scanTargetHost(m.Target)

	var portResults []portResult
	var err error
	if m.scan != nil {
		portResults, err = m.scan(ctx)
	} else {
		// Use the existing PortScanner component and scan top common ports.
		scanner := NewPortScanner(targetHost, []int{})
		scanner.SetThreads(m.MaxThreads)
		portResults, err = scanner.ScanCommonPorts(ctx)
	}
	if err != nil && ctx.Err() == nil {
		return m.results, err
	}

	openCount, closedCount, dialFailures := 0, 0, 0
	for _, pr := range portResults {
		switch pr.State {
		case "open":
			openCount++
			m.results = append(m.results, PortScanningResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: fmt.Sprintf("Port %d is open. Banner: %s", pr.Port, pr.Banner),
			})
		case "closed":
			closedCount++
		case "filtered":
			dialFailures++
		}
	}

	if openCount == 0 && ctx.Err() == nil {
		switch {
		case closedCount > 0 && dialFailures == 0:
			// A clean "all closed" verdict requires every scanned port to have
			// been definitively refused; any dial failure leaves those ports
			// unverified, so the run stays inconclusive.
			m.results = append(m.results, PortScanningResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, true),
				Detail: "Target host was reachable and all scanned common ports are closed.",
			})
		default:
			m.results = append(m.results, PortScanningResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: fmt.Sprintf("Port scan could not verify all common ports on %s: %d closed, %d of %d dial attempts errored (filtered); unverified ports need a reachable-network re-scan.", targetHost, closedCount, dialFailures, len(portResults)),
			})
		}
	}

	return m.results, ctx.Err()
}

// scanTargetHost extracts the bare hostname from a target URL, preserving
// IPv6 literals (e.g. "http://[::1]:8080/app" -> "::1").
func scanTargetHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Hostname()
	}

	host := strings.TrimPrefix(target, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.SplitN(host, "/", 2)[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

func init() {
	RegisterModule("port_scanning", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting PortScanning on: %s", target))

		tester := NewPortScanning(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
