package core

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// PortScanner performs TCP port scanning on a target host
type PortScanner struct {
	Target  string
	Ports   []int
	Timeout time.Duration
	Threads int
	results map[int]portResult
	mu      sync.Mutex
}

type portResult struct {
	Port   int    `json:"port"`
	State  string `json:"state"`
	Banner string `json:"banner,omitempty"`
}

// NewPortScanner creates a new port scanner instance
func NewPortScanner(target string, ports []int) *PortScanner {
	return &PortScanner{
		Target:  target,
		Ports:   ports,
		Timeout: 2 * time.Second,
		Threads: 100,
		results: make(map[int]portResult),
	}
}

// SetTimeout sets the connection timeout (default: 2s)
func (ps *PortScanner) SetTimeout(duration time.Duration) {
	ps.Timeout = duration
}

// SetThreads sets the number of concurrent scanning threads (default: 100)
func (ps *PortScanner) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	ps.Threads = count
}

// Scan performs the port scan and returns results
func (ps *PortScanner) Scan(ctx context.Context) ([]portResult, error) {
	var wg sync.WaitGroup
	jobs := make(chan int, len(ps.Ports))

	// Distribute port jobs across worker goroutines
	for i := 0; i < ps.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := ps.scanPort(ctx, port)
				ps.mu.Lock()
				ps.results[port] = result
				ps.mu.Unlock()
			}
		}()
	}

	// Send all ports to the job channel
	for _, port := range ps.Ports {
		jobs <- port
	}
	close(jobs)

	// Wait for all workers to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return ps.sortAndReturnResults(), nil
	case <-ctx.Done():
		<-done
		return ps.getPartialResults(), ctx.Err()
	}
}

// scanPort performs a TCP connect scan on a single port
func (ps *PortScanner) scanPort(ctx context.Context, port int) portResult {
	addr := net.JoinHostPort(ps.Target, fmt.Sprintf("%d", port))

	if ctx.Err() != nil {
		return portResult{Port: port, State: "closed", Banner: "context cancelled"}
	}

	dialer := net.Dialer{Timeout: ps.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return portResult{Port: port, State: "closed", Banner: "context cancelled"}
		}
		return portResult{Port: port, State: "filtered"}
	}
	defer conn.Close()

	// Try to read banner for open ports
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)

	if n > 0 {
		banner := string(buffer[:n])
		// Clean up banner for display
		if len(banner) > 200 {
			banner = banner[:200]
		}
		return portResult{Port: port, State: "open", Banner: banner}
	}

	return portResult{Port: port, State: "open"}
}

// sortAndReturnResults sorts results by port number and returns them as a slice
func (ps *PortScanner) sortAndReturnResults() []portResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	sorted := make([]int, 0, len(ps.results))
	for port := range ps.results {
		sorted = append(sorted, port)
	}

	sort.Ints(sorted)

	orderedResults := make([]portResult, len(sorted))
	for i, port := range sorted {
		orderedResults[i] = ps.results[port]
	}
	return orderedResults
}

// getPartialResults returns currently collected results during cancellation
func (ps *PortScanner) getPartialResults() []portResult {
	return ps.sortAndReturnResults()
}

// ScanCommonPorts scans a minimal set of highly common web and remote administration ports
func (ps *PortScanner) ScanCommonPorts(ctx context.Context) ([]portResult, error) {
	commonPorts := []int{
		21, 22, 80, 443, 3306, 5432, 8080, 8443,
	}
	ps.Ports = commonPorts
	return ps.Scan(ctx)
}
