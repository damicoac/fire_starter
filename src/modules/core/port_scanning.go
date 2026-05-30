package core

import (
	"context"
	"fmt"
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

	targetHost := strings.TrimPrefix(m.Target, "http://")
	targetHost = strings.TrimPrefix(targetHost, "https://")
	targetHost = strings.Split(targetHost, "/")[0]
	targetHost = strings.Split(targetHost, ":")[0]

	// Use the existing PortScanner component
	scanner := NewPortScanner(targetHost, []int{})
	scanner.SetThreads(m.MaxThreads)

	// We'll scan top common ports
	portResults, err := scanner.ScanCommonPorts(ctx)
	if err != nil && ctx.Err() == nil {
		return m.results, err
	}

	for _, pr := range portResults {
		if pr.State == "open" {
			m.RecordPoC(nil, nil, fmt.Sprintf("Port %d is open. Banner: %s", pr.Port, pr.Banner))
			m.results = append(m.results, PortScanningResult{
				Target: m.Target,
				Status: "found",
				Detail: fmt.Sprintf("Port %d is open. Banner: %s", pr.Port, pr.Banner),
			})
		}
	}

	return m.results, ctx.Err()
}

func init() {
	RegisterModule("port_scanning", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
