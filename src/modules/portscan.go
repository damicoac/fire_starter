package modules

import (
	"context"
	"fmt"
	"net"
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
		ps.sortAndReturnResults()
		return nil, nil
	case <-ctx.Done():
		return ps.getPartialResults(), ctx.Err()
	}
}

// scanPort performs a TCP connect scan on a single port
func (ps *PortScanner) scanPort(ctx context.Context, port int) portResult {
	addr := fmt.Sprintf("%s:%d", ps.Target, port)

	var conn net.Conn
	var err error

	if ctx.Err() != nil {
		return portResult{Port: port, State: "closed", Banner: "context cancelled"}
	}

	conn, err = net.DialTimeout("tcp", addr, ps.Timeout)
	if err != nil {
		return portResult{Port: port, State: "filtered"}
	}
	defer conn.Close()

	// Try to read banner for open ports
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
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
func (ps *PortScanner) sortAndReturnResults() {
	sorted := make([]int, 0, len(ps.results))
	for port := range ps.results {
		sorted = append(sorted, port)
	}

	// Simple insertion sort for efficiency on typically small datasets
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Convert to ordered results slice for consistent output
	orderedResults := make([]portResult, len(sorted))
	for i, port := range sorted {
		orderedResults[i] = ps.results[port]
	}

	// Update results with ordered data for JSON marshaling consistency
	ps.results = make(map[int]portResult)
	for i, result := range orderedResults {
		ps.results[orderedResults[i].Port] = result
	}
}

// getPartialResults returns currently collected results during cancellation
func (ps *PortScanner) getPartialResults() []portResult {
	ports := make([]int, 0, len(ps.results))
	for port := range ps.results {
		ports = append(ports, port)
	}

	// Sort ports
	for i := 1; i < len(ports); i++ {
		key := ports[i]
		j := i - 1
		for j >= 0 && ports[j] > key {
			ports[j+1] = ports[j]
			j--
		}
		ports[j+1] = key
	}

	resultSlice := make([]portResult, len(ports))
	for i, port := range ports {
		resultSlice[i] = ps.results[port]
	}

	return resultSlice
}

// ScanCommonPorts scans common ports (1-1024)
func (ps *PortScanner) ScanCommonPorts(ctx context.Context) ([]portResult, error) {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161,
		194, 443, 445, 465, 512, 513, 514, 587, 636,
		993, 995, 1433, 1434, 1521, 3306, 3389, 5432,
		5900, 6379, 8080, 8443,
	}
	ps.Ports = commonPorts
	return ps.Scan(ctx)
}

// ScanPortRange scans a range of ports (inclusive)
func (ps *PortScanner) ScanPortRange(start, end int) ([]portResult, error) {
	ports := make([]int, end-start+1)
	for i := start; i <= end; i++ {
		ports[i-start] = i
	}
	ps.Ports = ports
	return ps.Scan(context.Background())
}
