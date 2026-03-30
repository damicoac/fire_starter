package modules

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// PortScanningResult holds the result of the PortScanning module execution.
type PortScanningResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PortScanning executes the port_scanning security technique.
type PortScanning struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []PortScanningResult
}

// NewPortScanning creates a new instance.
func NewPortScanning(target string) *PortScanning {
	return &PortScanning{
		Target:     target,
		maxThreads: 10,
	}
}

func (m *PortScanning) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *PortScanning) Execute(ctx context.Context) ([]PortScanningResult, error) {
	m.results = make([]PortScanningResult, 0)

	targetHost := strings.TrimPrefix(m.Target, "http://")
	targetHost = strings.TrimPrefix(targetHost, "https://")
	targetHost = strings.Split(targetHost, "/")[0]
	targetHost = strings.Split(targetHost, ":")[0]

	// Use the existing PortScanner component
	scanner := NewPortScanner(targetHost, []int{})
	scanner.SetThreads(m.maxThreads)

	// We'll scan top common ports
	portResults, err := scanner.ScanCommonPorts(ctx)
	if err != nil && ctx.Err() == nil {
		return m.results, err
	}

	for _, pr := range portResults {
		if pr.State == "open" {
			m.results = append(m.results, PortScanningResult{
				Target: m.Target,
				Status: "found",
				Detail: fmt.Sprintf("Port %d is open. Banner: %s", pr.Port, pr.Banner),
			})
		}
	}

	return m.results, ctx.Err()
}
