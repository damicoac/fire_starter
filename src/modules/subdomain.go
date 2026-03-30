package modules

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// SubdomainEnumerator performs subdomain enumeration via brute-force and DNS queries
type SubdomainEnumerator struct {
	Target     string
	Wordlist   []string
	Results    map[string]bool
	done       chan struct{}
	mu         sync.Mutex
	maxThreads int
	results    []SubdomainResult
}

// SubdomainResult holds enumeration results
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
}

// NewSubdomainEnumerator creates a new subdomain enumerator instance
func NewSubdomainEnumerator(target string) *SubdomainEnumerator {
	return &SubdomainEnumerator{
		Target:     target,
		Wordlist:   getDefaultWordlist(),
		Results:    make(map[string]bool),
		done:       make(chan struct{}),
		maxThreads: 50,
	}
}

// SetThreads sets the number of concurrent enumeration threads (default: 50)
func (se *SubdomainEnumerator) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	se.maxThreads = count
}

// SetWordlist sets custom wordlist for brute-force enumeration
func (se *SubdomainEnumerator) SetWordlist(words []string) {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.Wordlist = words
}

// Enumerate performs the subdomain enumeration and returns results
func (se *SubdomainEnumerator) Enumerate(ctx context.Context) ([]SubdomainResult, error) {
	se.results = make([]SubdomainResult, 0)
	se.done = make(chan struct{})
	done := make(chan struct{})

	jobs := make(chan string, len(se.Wordlist))
	var wg sync.WaitGroup

	for _, domain := range se.Wordlist {
		jobs <- domain
	}
	close(jobs)

	for i := 0; i < se.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				select {
				case <-se.done:
					return
				default:
					candidate := fmt.Sprintf("%s.%s", domain, se.Target)
					if se.isSubdomain(ctx, candidate) {
						se.mu.Lock()
						se.Results[candidate] = true
						ips := se.lookupIPs(candidate)
						r := SubdomainResult{
							Subdomain: candidate,
							IPs:       ips,
						}
						se.results = append(se.results, r)
						se.mu.Unlock()
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		sort.Slice(se.results, func(i, j int) bool {
			return se.results[i].Subdomain < se.results[j].Subdomain
		})
		return se.results, nil
	case <-ctx.Done():
		close(se.done)
		<-done
		return se.results, ctx.Err()
	}
}

// isSubdomain checks if a candidate subdomain exists by attempting DNS resolution
func (se *SubdomainEnumerator) isSubdomain(ctx context.Context, subdomain string) bool {
	if ctx.Err() != nil {
		return false
	}

	resolver := &net.Resolver{}
	ops, err := resolver.LookupIPAddr(ctx, subdomain)
	if err == nil && len(ops) > 0 {
		return true
	}

	ip := net.ParseIP(subdomain)
	if ip != nil && !ip.IsUnspecified() {
		return true
	}

	nets, err := net.LookupIP(subdomain)
	if err == nil && len(nets) > 0 {
		for _, addr := range nets {
			if !addr.IsUnspecified() && !addr.IsLoopback() {
				return true
			}
		}
	}

	return false
}

// lookupIPs resolves a subdomain to its IP addresses
func (se *SubdomainEnumerator) lookupIPs(subdomain string) []string {
	var ips []string

	resolver := &net.Resolver{}
	ops, err := resolver.LookupIPAddr(context.Background(), subdomain)
	if err != nil {
		return ips
	}

	for _, op := range ops {
		ips = append(ips, op.IP.String())
	}

	if len(ips) == 0 {
		nets, err := net.LookupIP(subdomain)
		if err == nil {
			for _, addr := range nets {
				if !addr.IsUnspecified() && !addr.IsLoopback() {
					ips = append(ips, addr.String())
				}
			}
		}
	}

	return ips
}

// getDefaultWordlist returns a common subdomain wordlist for brute-force enumeration
func getDefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "api", "admin", "dev", "staging",
		"test", "prod", "stage", "qa", "sandbox", "demo",
		"app", "web", "smtp", "pop3", "imap", "dns",
		"ns1", "ns2", "mx", "ns", "cdn", "static",
		"assets", "media", "img", "images", "files",
		"blog", "shop", "store", "docs", "help",
		"support", "portal", "dashboard", "login", "auth",
		"api-v1", "api-v2", "v1", "v2", "graphql",
		"git", "svn", "hg", "cvs", "ci", "cd",
		"jenkins", "travis", "circleci", "github",
		"status", "health", "metrics", "monitoring",
		"prometheus", "grafana", "elk", "kibana",
		"elastic", "logs", "logging",
		"internal", "private", "secure", "vault",
		"keyserver", "ldap", "radius", "acs",
		"sso", "oauth", "oidc",
		"auth0", "okta", "azuread", "identity",
		"cdn1", "cdn2", "edge", "origin",
		"backup", "archive", "old", "legacy",
		"deprecated", "temp",
		"mobile", "ios", "android", "webapp",
		"m", "m2", "mobile-api", "api-mobile",
		"dev1", "dev2", "staging1", "staging2",
		"uat", "preprod", "production", "prod1", "prod2",
		"db", "database", "mysql", "postgres", "mongo",
		"redis", "memcached", "cache", "elasticsearch",
		"search", "index", "crawler", "bot",
		"webmail", "cpanel", "whm",
		"ftp1", "ftp2", "ftptest", "sftp-test",
		"smtp-relay", "mail-relay", "mx1", "mx2",
		"webdav", "dav",
		"zookeeper", "kafka", "rabbitmq",
		"jira", "confluence", "wiki", "redmine",
		"gitlab", "gerrit",
		"cloudfront", "aws", "azure",
		"gcp", "office365", "sharepoint",
		"teams", "zendesk", "salesforce", "hubspot",
	}
}

// EnumerateWithPorts performs enumeration and scans common HTTP/S ports on discovered subdomains
func (se *SubdomainEnumerator) EnumerateWithPorts(ctx context.Context) ([]SubdomainResult, error) {
	se.results = make([]SubdomainResult, 0)
	baseResults, err := se.Enumerate(ctx)
	if err != nil {
		return nil, err
	}

	const httpPorts = 80
	const httpsPort = 443

	var extendedResults []SubdomainResult
	for _, r := range baseResults {
		if len(r.IPs) == 0 {
			extendedResults = append(extendedResults, r)
			continue
		}

		for _, ip := range r.IPs {
			var openPorts []string

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, httpPorts), 2*time.Second)
			if err == nil {
				openPorts = append(openPorts, fmt.Sprintf("%d", httpPorts))
				conn.Close()
			}

			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, httpsPort), 2*time.Second)
			if err == nil {
				p := fmt.Sprintf("%d", httpsPort)
				openPorts = append(openPorts, p)
				conn.Close()
			}

			n := SubdomainResult{
				Subdomain: r.Subdomain,
				IPs:       append(openPorts, ip),
			}
			extendedResults = append(extendedResults, n)
		}
	}

	sort.Slice(extendedResults, func(i, j int) bool {
		return extendedResults[i].Subdomain < extendedResults[j].Subdomain
	})

	return extendedResults, nil
}
