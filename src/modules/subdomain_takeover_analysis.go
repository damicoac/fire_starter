package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// SubdomainTakeoverAnalysisResult holds the result of the SubdomainTakeoverAnalysis module execution.
type SubdomainTakeoverAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SubdomainTakeoverAnalysis executes the subdomain_takeover_analysis security technique.
type SubdomainTakeoverAnalysis struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []SubdomainTakeoverAnalysisResult
}

// NewSubdomainTakeoverAnalysis creates a new instance.
func NewSubdomainTakeoverAnalysis(target string) *SubdomainTakeoverAnalysis {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	return &SubdomainTakeoverAnalysis{
		Target:     target,
		maxThreads: 5,
	}
}

func (m *SubdomainTakeoverAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var takeoverSignatures = []string{
	"s3.amazonaws.com",
	"github.io",
	"herokuapp.com",
	"zendesk.com",
	"azurewebsites.net",
}

func (m *SubdomainTakeoverAnalysis) Execute(ctx context.Context) ([]SubdomainTakeoverAnalysisResult, error) {
	m.results = make([]SubdomainTakeoverAnalysisResult, 0)

	// In a real run, this would be a full wordlist, but we'll use a small set for simulation
	testSubs := []string{"help", "docs", "blog", "app", "dev", "status"}

	jobs := make(chan string, len(testSubs))
	for _, sub := range testSubs {
		jobs <- fmt.Sprintf("%s.%s", sub, m.Target)
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testSubdomain(ctx, job)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *SubdomainTakeoverAnalysis) testSubdomain(ctx context.Context, sub string) {
	cname, err := net.LookupCNAME(sub)
	if err != nil {
		return
	}

	for _, sig := range takeoverSignatures {
		if strings.Contains(cname, sig) {
			m.mu.Lock()
			m.results = append(m.results, SubdomainTakeoverAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Subdomain " + sub + " points to vulnerable 3rd party service CNAME: " + cname,
			})
			m.mu.Unlock()
			return
		}
	}
}
