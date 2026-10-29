package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SubdomainTakeoverAnalysisResult holds the result of the SubdomainTakeoverAnalysis module execution.
type SubdomainTakeoverAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func defaultLookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

// SubdomainTakeoverAnalysis executes the subdomain_takeover_analysis security technique.
type SubdomainTakeoverAnalysis struct {
	BaseModule
	Target      string
	results     []SubdomainTakeoverAnalysisResult
	LookupCNAME func(ctx context.Context, host string) (string, error)
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
		Target:      target,
		LookupCNAME: defaultLookupCNAME,
	}
}

func (m *SubdomainTakeoverAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var takeoverSignatures = map[string]string{
	"s3.amazonaws.com":  "NoSuchBucket",
	"github.io":         "There isn't a GitHub Pages site here",
	"herokuapp.com":     "No such app",
	"zendesk.com":       "Help Center Closed",
	"azurewebsites.net": "404 Web Site not found",
}

func (m *SubdomainTakeoverAnalysis) Execute(ctx context.Context) ([]SubdomainTakeoverAnalysisResult, error) {
	m.results = make([]SubdomainTakeoverAnalysisResult, 0)

	wordlist := getDefaultWordlist()
	jobs := make(chan string, len(wordlist))
	for _, sub := range wordlist {
		jobs <- fmt.Sprintf("%s.%s", sub, m.Target)
	}
	close(jobs)

	var resolvedCount int64
	var failureCount int64
	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					if m.testSubdomain(ctx, job) {
						atomic.AddInt64(&resolvedCount, 1)
					} else {
						atomic.AddInt64(&failureCount, 1)
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
	case <-ctx.Done():
		<-done
		m.appendInconclusiveIfUnresolved(resolvedCount, failureCount)
		return m.results, ctx.Err()
	}

	m.appendInconclusiveIfUnresolved(resolvedCount, failureCount)
	return m.results, nil
}

func (m *SubdomainTakeoverAnalysis) appendInconclusiveIfUnresolved(resolvedCount, failureCount int64) {
	if resolvedCount > 0 || failureCount == 0 {
		return
	}
	m.Mu.Lock()
	m.results = append(m.results, SubdomainTakeoverAnalysisResult{
		Target: m.Target,
		Status: "inconclusive",
		Detail: fmt.Sprintf("No subdomain could be resolved (%d DNS lookups failed); takeover status unknown.", failureCount),
	})
	m.Mu.Unlock()
}

func (m *SubdomainTakeoverAnalysis) testSubdomain(ctx context.Context, sub string) bool {
	lookup := m.LookupCNAME
	if lookup == nil {
		lookup = defaultLookupCNAME
	}
	cname, err := lookup(ctx, sub)
	if err != nil {
		return false
	}

	for cnameSig, errorSig := range takeoverSignatures {
		if strings.Contains(cname, cnameSig) {
			// Actually fetch the page to see if it's available for takeover.
			// Try HTTPS first (GitHub Pages/Heroku are HTTPS-only), fall back to HTTP.
			if !m.probeTakeover(ctx, sub, "https", cname, errorSig) {
				m.probeTakeover(ctx, sub, "http", cname, errorSig)
			}
		}
	}
	return true
}

func (m *SubdomainTakeoverAnalysis) probeTakeover(ctx context.Context, sub, scheme, cname, errorSig string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+"://"+sub, nil)
	if err != nil {
		return false
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		// An unreadable body proves nothing; report "not verified" so the
		// http:// fallback scheme still runs.
		return false
	}

	if strings.Contains(string(bodyBytes), errorSig) {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Subdomain "+sub+" is vulnerable to takeover via "+cname)
		m.results = append(m.results, SubdomainTakeoverAnalysisResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Subdomain " + sub + " is vulnerable to takeover via " + cname,
		})
		m.Mu.Unlock()
	}
	return true
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
