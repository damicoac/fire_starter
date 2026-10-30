package agent

import (
	"fmt"
	"net"
	"strings"
)

// ExtractIPsFromTarget resolves a target string (bare IP, hostname, or URL) to
// the IP addresses it refers to, erroring when nothing resolves. It backs
// LoopbackScopeAllow and ConfigScopeAllow so every scope guard applies
// identical resolution and deny-on-unresolvable rules.
func ExtractIPsFromTarget(target string) ([]string, error) {
	ips := extractIPsFromTarget(target)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses could be resolved for target %q", target)
	}
	return ips, nil
}

// LoopbackScopeAllow returns a scope guard that only accepts targets which
// resolve exclusively to loopback addresses (127.0.0.0/8, ::1). It is the
// deny-by-default fallback for the MCP server when no engagement config is
// available: with no declared scope, nothing outside the operator's own
// machine may be attacked.
func LoopbackScopeAllow() func(target string) bool {
	return func(target string) bool {
		ips, err := ExtractIPsFromTarget(target)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil || !parsed.IsLoopback() {
				return false
			}
		}
		return true
	}
}

// ConfigScopeAllow returns a scope guard derived from the engagement config:
// the allowed set is cfg.IPWhitelist plus every IP that cfg.Target resolves
// to. A target is in scope only when every address it resolves to belongs to
// that set; targets that cannot be resolved at all are rejected (fail closed),
// which also blocks DNS-rebinding style escapes where only some resolved
// addresses are authorized.
func ConfigScopeAllow(cfg Config) func(target string) bool {
	allowed := make(map[string]bool)
	for _, entry := range cfg.IPWhitelist {
		trimmed := strings.TrimSpace(entry)
		if parsed := net.ParseIP(trimmed); parsed != nil {
			allowed[parsed.String()] = true
			continue
		}
		// Whitelist entries may be hostnames; resolve them the same way the
		// workflow allowlist seeds IPs. Unresolvable entries simply
		// contribute nothing.
		for _, ip := range extractIPsFromTarget(trimmed) {
			allowed[ip] = true
		}
	}
	for _, ip := range extractIPsFromTarget(cfg.Target) {
		allowed[ip] = true
	}
	return func(target string) bool {
		ips, err := ExtractIPsFromTarget(target)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if !allowed[ip] {
				return false
			}
		}
		return true
	}
}
