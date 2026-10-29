package core

import (
	"context"
	"crypto/rand"
	"errors"
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
	Target   string
	results  []SubdomainEnumerationResult
	resolve  func(host string) ([]string, error)
	wordlist []string
}

// NewSubdomainEnumeration creates a new instance of SubdomainEnumeration.
func NewSubdomainEnumeration(target string) *SubdomainEnumeration {
	// Strip scheme, path and port: DNS lookups need a bare hostname.
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.Index(target, "/"); idx >= 0 {
		target = target[:idx]
	}
	if idx := strings.Index(target, ":"); idx >= 0 {
		target = target[:idx]
	}
	return &SubdomainEnumeration{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target:   target,
		wordlist: getDefaultWordlist(),
	}
}

// SetResolver injects a custom DNS resolution function (used by tests).
func (m *SubdomainEnumeration) SetResolver(fn func(host string) ([]string, error)) {
	m.resolve = fn
}

// SetWordlist injects a custom wordlist (used by tests).
func (m *SubdomainEnumeration) SetWordlist(words []string) {
	m.wordlist = words
}

func (m *SubdomainEnumeration) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *SubdomainEnumeration) Execute(ctx context.Context) ([]SubdomainEnumerationResult, error) {
	m.results = make([]SubdomainEnumerationResult, 0)

	if m.Target == "" {
		m.addResult("No resolvable target hostname after normalization", statusFromEvidence(EvidenceWeak, false))
		return m.results, nil
	}

	wordlist := m.wordlist
	if len(wordlist) == 0 {
		wordlist = getDefaultWordlist()
	}
	resolve := m.resolve
	if resolve == nil {
		resolve = net.LookupHost
	}

	// Wildcard-DNS control probe: a random label under the target should
	// never resolve. If it does, every wordlist candidate resolves too and
	// results are filtered against the wildcard IP set. The control probe goes
	// through lookupWithRetry so a single transient failure cannot empty the
	// wildcard set and mass-flag the whole wordlist.
	wildcardIPs := make(map[string]bool)
	if controlLabel := randomHexLabel(); controlLabel != "" {
		controlHost := fmt.Sprintf("%s.%s", controlLabel, m.Target)
		if ips, err := lookupWithRetry(ctx, controlHost, resolve); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				wildcardIPs[ip] = true
			}
			m.addResult(fmt.Sprintf("Wildcard DNS detected: control host %s resolves; candidate results are filtered against the wildcard IP set", controlHost), statusFromEvidence(EvidenceWeak, false))
		}
	}

	jobs := make(chan string, len(wordlist))
	for _, sub := range wordlist {
		jobs <- fmt.Sprintf("%s.%s", sub, m.Target)
	}
	close(jobs)

	var (
		wg            sync.WaitGroup
		countMu       sync.Mutex
		resolvedCount int
		otherErrCount int
	)

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ips, err := lookupWithRetry(ctx, job, resolve)

				countMu.Lock()
				switch {
				case err == nil && len(ips) > 0:
					if allInWildcard(ips, wildcardIPs) {
						// Wildcard answer: not a real subdomain.
					} else {
						resolvedCount++
						m.addResult(fmt.Sprintf("Subdomain %s resolved to %s", job, strings.Join(ips, ", ")), statusFromEvidence(EvidenceConfirmed, false))
					}
				case isNXDOMAIN(err):
					// Definitive negative.
				case err != nil:
					otherErrCount++
				}
				countMu.Unlock()
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
	}

	sort.Slice(m.results, func(i, j int) bool {
		return m.results[i].Detail < m.results[j].Detail
	})

	// Only summarize when the run completed: a cancelled scan must not be
	// reported as a clean or failed one.
	if ctx.Err() == nil {
		if resolvedCount == 0 && otherErrCount > 0 {
			m.addResult(fmt.Sprintf("DNS resolution failed for %d of %d candidates (non-NXDOMAIN errors); results unreliable", otherErrCount, len(wordlist)), statusFromEvidence(EvidenceWeak, false))
		} else if resolvedCount == 0 {
			m.addResult("No subdomains resolved from the wordlist", statusFromEvidence(EvidenceConfirmed, true))
		}
	}

	return m.results, ctx.Err()
}

// lookupWithRetry retries transient DNS failures; NXDOMAIN is definitive and
// never retried.
func lookupWithRetry(ctx context.Context, host string, resolve func(string) ([]string, error)) ([]string, error) {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond
	var ips []string
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		ips, err = resolve(host)
		if err == nil || isNXDOMAIN(err) || ctx.Err() != nil {
			return ips, err
		}
		time.Sleep(baseDelay * time.Duration(1<<attempt))
	}
	return ips, err
}

func isNXDOMAIN(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func allInWildcard(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcardIPs[ip] {
			return false
		}
	}
	return true
}

func randomHexLabel() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func (m *SubdomainEnumeration) addResult(detail, status string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.results = append(m.results, SubdomainEnumerationResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
}

func init() {
	RegisterModule("subdomain_enumeration", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
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
