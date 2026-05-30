package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SubdomainTakeoverAnalysisResult holds the result of the SubdomainTakeoverAnalysis module execution.
type SubdomainTakeoverAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SubdomainTakeoverAnalysis executes the subdomain_takeover_analysis security technique.
type SubdomainTakeoverAnalysis struct {
	BaseModule
	Target  string
	results []SubdomainTakeoverAnalysisResult
}

// NewSubdomainTakeoverAnalysis creates a new instance.
func NewSubdomainTakeoverAnalysis(target string) *SubdomainTakeoverAnalysis {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	return &SubdomainTakeoverAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target,
	}
}

func (m *SubdomainTakeoverAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	for i := 0; i < m.MaxThreads; i++ {
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
			m.Mu.Lock()
			m.RecordPoC(nil, nil, "Subdomain "+sub+" points to vulnerable 3rd party service CNAME: "+cname)
			m.results = append(m.results, SubdomainTakeoverAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: "Subdomain " + sub + " points to vulnerable 3rd party service CNAME: " + cname,
			})
			m.Mu.Unlock()
			return
		}
	}
}

func init() {
	RegisterModule("subdomain_takeover_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting SubdomainTakeoverAnalysis on: %s", target))

		tester := NewSubdomainTakeoverAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
