package matrix

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"charm.land/fantasy"
)

func TestKnowledgeGraph_Scoring(t *testing.T) {
	kg := NewKnowledgeGraph()

	// Test IP Scoring
	kg.AddIP("192.168.1.1")
	target := kg.Targets["192.168.1.1"]
	if target == nil || target.Score != 1 {
		t.Errorf("Expected IP score 1, got %v", target)
	}

	kg.AddIP("192.168.1.1")
	if target.Score != 2 {
		t.Errorf("Expected IP score 2 after second add, got %d", target.Score)
	}

	// Test Port Scoring
	kg.AddPort("192.168.1.1", 80)
	if target.Score != 12 { // 2 + 10
		t.Errorf("Expected IP score 12 after adding port, got %d", target.Score)
	}

	// Test URL Scoring
	kg.AddURL("http://example.com", "")
	targetUrl := kg.Targets["example.com"]
	if targetUrl == nil || targetUrl.Score != 1 {
		t.Errorf("Expected URL score 1, got %v", targetUrl)
	}

	kg.AddURL("http://example.com?id=1", "")
	if kg.Targets["example.com?id=1"] != nil {
		t.Errorf("Expected parameterized URL to be folded into base target")
	}
	if targetUrl.Score != 7 { // 1 (from http://example.com) + 6 (from http://example.com?id=1)
		t.Errorf("Expected URL score 7 for param URL folded into base target, got %d", targetUrl.Score)
	}

	// Test www normalization
	kg.AddURL("http://www.example.com", "")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected URL to be normalized and merged")
	}
	kg.AddURL("https://www.example.com", "")
	if kg.Targets["www.example.com"] != nil {
		t.Errorf("Expected https://www.example.com to be merged as well")
	}
	kg.AddURL("www.test.com", "")
	targetTest := kg.Targets["test.com"]
	if targetTest == nil || targetTest.Value != "test.com" {
		t.Errorf("Expected www.test.com to be normalized to test.com")
	}
}

func TestKnowledgeGraph_GetTokensForTarget(t *testing.T) {
	kg := NewKnowledgeGraph()

	kg.AddToken("example.com", "default", "cookie_example=1")
	kg.AddToken("sub.example.com", "default", "cookie_sub=1")
	kg.AddToken("other.com", "default", "cookie_other=1")
	kg.AddToken("192.168.1.1", "default", "cookie_ip1=1")
	kg.AddToken("192.168.1.2", "default", "cookie_ip2=1")

	// Helper to check if slice contains element
	contains := func(slice []string, val string) bool {
		for _, s := range slice {
			if s == val {
				return true
			}
		}
		return false
	}

	// Test 1: exact match
	tokens := kg.GetTokensForTarget("example.com/api/v1")
	if !contains(tokens, "cookie_example=1") {
		t.Errorf("Expected tokens to contain cookie_example, got %v", tokens)
	}
	if contains(tokens, "cookie_other=1") {
		t.Errorf("Expected tokens NOT to contain cookie_other, got %v", tokens)
	}

	// Test 2: subdomain retrieval (should get both example.com and sub.example.com tokens)
	tokensSub := kg.GetTokensForTarget("sub.example.com/test")
	if !contains(tokensSub, "cookie_sub=1") || !contains(tokensSub, "cookie_example=1") {
		t.Errorf("Expected sub.example.com tokens to contain both cookie_sub and cookie_example, got %v", tokensSub)
	}
	if contains(tokensSub, "cookie_other=1") {
		t.Errorf("Expected sub.example.com tokens NOT to contain cookie_other, got %v", tokensSub)
	}

	// Test 3: parent domain retrieval (should get sub.example.com tokens as well because they share domain scope)
	tokensParent := kg.GetTokensForTarget("example.com")
	if !contains(tokensParent, "cookie_example=1") || !contains(tokensParent, "cookie_sub=1") {
		t.Errorf("Expected example.com tokens to contain both cookie_example and cookie_sub, got %v", tokensParent)
	}

	// Test 4: unrelated domain isolation
	tokensOther := kg.GetTokensForTarget("other.com")
	if !contains(tokensOther, "cookie_other=1") {
		t.Errorf("Expected other.com tokens to contain cookie_other, got %v", tokensOther)
	}
	if contains(tokensOther, "cookie_example=1") || contains(tokensOther, "cookie_sub=1") {
		t.Errorf("Expected other.com tokens NOT to contain example cookies, got %v", tokensOther)
	}

	// Test 5: IP isolation
	tokensIP1 := kg.GetTokensForTarget("192.168.1.1")
	if !contains(tokensIP1, "cookie_ip1=1") {
		t.Errorf("Expected 192.168.1.1 tokens to contain cookie_ip1, got %v", tokensIP1)
	}
	if contains(tokensIP1, "cookie_ip2=1") {
		t.Errorf("Expected 192.168.1.1 tokens NOT to contain cookie_ip2, got %v", tokensIP1)
	}
}

func TestMatchDomainOrIP(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", "example.com", false},
		{"example.com", "*.example.com", true},
		{"sub.example.com", "*.example.com", true},
		{"sub.sub.example.com", "*.example.com", true},
		{"other.com", "*.example.com", false},
		{"example.com.attacker.com", "*.example.com", false},
		{"notexample.com", "*.example.com", false},
		{"example.co.uk", "*.example.co.uk", true},
		{"foo.example.co.uk", "*.example.co.uk", true},
		{"foo.example.co.uk", "co.uk", false},
		{"192.168.1.5", "192.168.1.*", true},
		{"192.168.2.5", "192.168.1.*", false},
		{"10.0.0.1", "*", true},
	}

	for _, tt := range tests {
		got := MatchDomainOrIP(tt.input, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchDomainOrIP(%q, %q) = %v, want %v", tt.input, tt.pattern, got, tt.want)
		}
	}
}

func TestKnowledgeGraph_TargetDomainsWhitelist(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"*.example.com", "192.168.1.*"}

	// URL within whitelist
	kg.AddURL("http://example.com/api", "")
	if kg.Targets["example.com/api"] == nil {
		t.Errorf("Expected example.com/api to be ingested")
	}

	// Subdomain URL within whitelist
	kg.AddURL("https://sub.example.com/test", "")
	if kg.Targets["sub.example.com/test"] == nil {
		t.Errorf("Expected sub.example.com/test to be ingested")
	}

	// URL outside whitelist
	kg.AddURL("http://attacker.com/api", "")
	if kg.Targets["attacker.com/api"] != nil {
		t.Errorf("Expected attacker.com/api to be ignored")
	}

	// IP matching wildcard pattern
	kg.AddIP("192.168.1.100")
	if kg.Targets["192.168.1.100"] == nil {
		t.Errorf("Expected 192.168.1.100 to be ingested via wildcard match")
	}

	// IP not matching wildcard pattern
	kg.AddIP("10.0.0.1")
	if kg.Targets["10.0.0.1"] != nil {
		t.Errorf("Expected 10.0.0.1 to be ignored")
	}

	// Dynamically allowed IP (manually added or resolved)
	kg.AddAllowedIP("8.8.8.8")
	kg.AddIP("8.8.8.8")
	if kg.Targets["8.8.8.8"] == nil {
		t.Errorf("Expected 8.8.8.8 to be ingested via dynamic allowed list")
	}
}

func TestKnowledgeGraph_AddURLAllowsSeededSubdomainWithoutManualWildcard(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"app.example.com", "*.app.example.com"}

	kg.AddURL("https://app.example.com/login", "https://app.example.com")

	if kg.Targets["app.example.com/login"] == nil {
		t.Fatalf("expected seeded subdomain target to be ingested")
	}
}

func TestKnowledgeGraph_AddURLDoesNotRescoreDuplicateURL(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"example.com", "*.example.com"}

	kg.AddURL("https://example.com/login", "https://example.com")
	target := kg.Targets["example.com/login"]
	if target == nil {
		t.Fatalf("expected login target to be ingested")
	}
	initialScore := target.Score

	kg.AddURL("https://example.com/login", "https://example.com")
	if target.Score != initialScore {
		t.Fatalf("expected duplicate URL discovery to keep score %d, got %d", initialScore, target.Score)
	}
}

func TestKnowledgeGraph_AddURLRejectsStaticAssets(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"example.com", "*.example.com"}

	kg.AddURL("https://example.com/assets/site.css", "https://example.com")
	kg.AddURL("https://example.com/static/app.js", "https://example.com")

	if kg.Targets["example.com/assets/site.css"] != nil {
		t.Fatalf("expected css asset to be ignored")
	}
	if kg.Targets["example.com/static/app.js"] != nil {
		t.Fatalf("expected js asset to be ignored")
	}
}

func TestKnowledgeGraph_AddURLResolvesRelativePaths(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"example.com", "*.example.com"}

	kg.AddURL("/admin/login", "https://example.com/base")

	if kg.Targets["example.com/admin/login"] == nil {
		t.Fatalf("expected relative path to resolve against base target")
	}
}

type mockModel struct {
	fantasy.LanguageModel
	responseStr string
	err         error
}

func (m *mockModel) Generate(ctx context.Context, call fantasy.Call) (*fantasy.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &fantasy.Response{
		Content: fantasy.ResponseContent{
			fantasy.TextContent{Text: m.responseStr},
		},
	}, nil
}

func TestKnowledgeGraph_EvaluateScopeWithLLM(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"*.example.com", "192.168.1.*"}

	mockJSON := `{
		"results": [
			{"candidate": "sub.example.com", "should_add": true, "reason": "subdomain"},
			{"candidate": "attacker.com", "should_add": false, "reason": "unrelated"},
			{"candidate": "192.168.1.1", "should_add": true, "reason": "in scope"}
		]
	}`

	model := &mockModel{
		responseStr: mockJSON,
	}

	ips := []string{"192.168.1.1"}
	urls := []string{"sub.example.com", "attacker.com"}

	allowedIPs, allowedURLs := kg.evaluateScopeWithLLM(context.Background(), model, ips, urls)

	if len(allowedIPs) != 1 || allowedIPs[0] != "192.168.1.1" {
		t.Errorf("Expected 192.168.1.1 to be allowed, got: %v", allowedIPs)
	}

	if len(allowedURLs) != 1 || allowedURLs[0] != "sub.example.com" {
		t.Errorf("Expected sub.example.com to be allowed, got: %v", allowedURLs)
	}
}

func TestKnowledgeGraph_EvaluateScopeWithLLMFallbackUsesScopeFilter(t *testing.T) {
	kg := NewKnowledgeGraph()
	kg.TargetDomains = []string{"*.example.com", "192.168.1.*"}

	ips := []string{"192.168.1.10", "10.0.0.5"}
	urls := []string{"sub.example.com", "attacker.com"}

	allowedIPs, allowedURLs := kg.evaluateScopeWithLLM(context.Background(), &mockModel{err: context.DeadlineExceeded}, ips, urls)

	if len(allowedIPs) != 1 || allowedIPs[0] != "192.168.1.10" {
		t.Fatalf("expected only in-scope IPs after fallback, got %v", allowedIPs)
	}

	if len(allowedURLs) != 1 || allowedURLs[0] != "sub.example.com" {
		t.Fatalf("expected only in-scope URLs after fallback, got %v", allowedURLs)
	}
}

func TestAddTestCase_PhaseFiltering(t *testing.T) {
	// Reset the singleton database instance for testing
	if dbInstance != nil {
		_ = dbInstance.Close()
	}
	dbInstance = nil
	dbMu = sync.Mutex{}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_add_testcase.db")
	_, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// Helper to count entries in database
	countVulns := func() int {
		v, err := GetVulnerabilities()
		if err != nil {
			t.Fatalf("GetVulnerabilities failed: %v", err)
		}
		return len(v)
	}

	// Truncate table first to ensure a clean state
	_, err = dbInstance.Exec("DELETE FROM vuln")
	if err != nil {
		t.Fatalf("failed to truncate vuln table: %v", err)
	}

	kg := NewKnowledgeGraph()
	targetVal := "test-target.com"

	// 1. Target is in PhaseVulnerabilityAnalysis (Discovery phase)
	target := kg.getOrCreateTarget(targetVal, "url")
	target.CurrentPhase = PhaseVulnerabilityAnalysis

	tc1 := TestCase{
		ToolName:    "discovery_tool",
		Target:      targetVal,
		Payload:     `{"q": "test"}`,
		Description: "Potential SQL Injection",
	}

	kg.AddTestCase(tc1)

	// Verify it was logged to DB as an unresolved candidate
	if count := countVulns(); count != 1 {
		t.Fatalf("Expected 1 logged vulnerability during discovery phase, got %d", count)
	}
	vulns, err := GetVulnerabilities()
	if err != nil {
		t.Fatalf("GetVulnerabilities failed: %v", err)
	}
	if vulns[0].Exploitable != "no" {
		t.Errorf("Expected exploitable status 'no' during discovery phase, got %q", vulns[0].Exploitable)
	}
	if vulns[0].Processed != "no" {
		t.Errorf("Expected processed status 'no' during discovery phase, got %q", vulns[0].Processed)
	}
	if vulns[0].Status != VulnerabilityStatusCandidate {
		t.Errorf("Expected status %q during discovery phase, got %q", VulnerabilityStatusCandidate, vulns[0].Status)
	}

	// 2. Target is in PhaseExploitation (Exploit phase)
	target.CurrentPhase = PhaseExploitation

	tc2 := TestCase{
		ToolName:    "exploit_tool",
		Target:      targetVal,
		Payload:     `{"q": "exploit"}`,
		Description: "Confirmed SQL Injection",
	}

	kg.AddTestCase(tc2)

	// Verify no additional DB log was created in exploitation phase (manual log_vulnerability required)
	if count := countVulns(); count != 1 {
		t.Errorf("Expected vulnerability count to remain 1 during exploit phase, got %d", count)
	}

	// 3. Target is in PhasePostExploitation (Post-exploit phase)
	target.CurrentPhase = PhasePostExploitation

	tc3 := TestCase{
		ToolName:    "post_exploit_tool",
		Target:      targetVal,
		Payload:     `{"cmd": "whoami"}`,
		Description: "Post-Exploit Finding",
	}

	kg.AddTestCase(tc3)

	// Verify no additional DB log was created in post-exploitation phase
	if count := countVulns(); count != 1 {
		t.Errorf("Expected vulnerability count to remain 1 during post-exploit phase, got %d", count)
	}
}
