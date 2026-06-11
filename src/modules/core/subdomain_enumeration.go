package core

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubdomainEnumerationResult holds the result of the SubdomainEnumeration module execution.
type SubdomainEnumerationResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SubdomainEnumeration executes the subdomain_enumeration security technique.
type SubdomainEnumeration struct {
	BaseModule
	Target  string
	results []SubdomainEnumerationResult
}

// NewSubdomainEnumeration creates a new instance of SubdomainEnumeration.
func NewSubdomainEnumeration(target string) *SubdomainEnumeration {
	// Strip http/https prefix if provided
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	return &SubdomainEnumeration{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target,
	}
}

func (m *SubdomainEnumeration) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}



func (m *SubdomainEnumeration) Execute(ctx context.Context) ([]SubdomainEnumerationResult, error) {
	m.results = make([]SubdomainEnumerationResult, 0)
	wordlist := getDefaultWordlist()
	jobs := make(chan string, len(wordlist))
	var wg sync.WaitGroup

	for _, sub := range wordlist {
		jobs <- fmt.Sprintf("%s.%s", sub, m.Target)
	}
	close(jobs)

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					var ips []string
					var err error
					maxRetries := 3
					baseDelay := 100 * time.Millisecond
					
					for attempt := 0; attempt < maxRetries; attempt++ {
						ips, err = net.LookupHost(job)
						if err == nil {
							break
						}
						if ctx.Err() != nil {
							break
						}
						time.Sleep(baseDelay * time.Duration(1<<attempt))
					}

					if err == nil && len(ips) > 0 {
						m.Mu.Lock()
						m.RecordPoC(nil, nil, fmt.Sprintf("Subdomain %s resolved to %s", job, strings.Join(ips, ", ")))
						m.results = append(m.results, SubdomainEnumerationResult{
							Target: m.Target,
							Status: "found",
							Detail: fmt.Sprintf("Subdomain %s resolved to %s", job, strings.Join(ips, ", ")),
						})
						m.Mu.Unlock()
					}
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		sort.Slice(m.results, func(i, j int) bool {
			return m.results[i].Detail < m.results[j].Detail
		})
		return m.results, nil
	case <-ctx.Done():
		<-done
		sort.Slice(m.results, func(i, j int) bool {
			return m.results[i].Detail < m.results[j].Detail
		})
		return m.results, ctx.Err()
	}
}

func init() {
	RegisterModule("subdomain_enumeration", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting SubdomainEnumeration on: %s", target))

		tester := NewSubdomainEnumeration(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
