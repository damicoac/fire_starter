package agent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fire_starter/src/matrix"
)

func TestRequiresCredentialValidation(t *testing.T) {
	testCases := []struct {
		name    string
		finding string
		want    bool
	}{
		{name: "env leak", finding: "Exposed .env file containing sensitive credentials", want: true},
		{name: "credential leak wording", finding: "Public credential disclosure in debug endpoint", want: true},
		{name: "generic vuln", finding: "SQL Injection on search parameter", want: false},
		{name: "blank finding", finding: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := requiresCredentialValidation(tc.finding)
			if got != tc.want {
				t.Fatalf("requiresCredentialValidation(%q) = %v, want %v", tc.finding, got, tc.want)
			}
		})
	}
}

func TestCredentialUseEvidenceInTestCode(t *testing.T) {
	testCases := []struct {
		name     string
		testCode string
		want     bool
	}{
		{name: "successful auth evidence", testCode: "Attempted login with leaked username/password and authenticated successfully (HTTP 200)", want: true},
		{name: "attempt only", testCode: "Tried leaked credentials against login endpoint but authentication failed", want: false},
		{name: "success only", testCode: "Received HTTP 200 from health check", want: false},
		{name: "blank", testCode: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := credentialUseEvidenceInTestCode(tc.testCode)
			if got != tc.want {
				t.Fatalf("credentialUseEvidenceInTestCode(%q) = %v, want %v", tc.testCode, got, tc.want)
			}
		})
	}
}

func TestCollectHelperVulnQueueOnlyReturnsCandidates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fire_starter.db")
	if _, err := matrix.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	kg := matrix.NewKnowledgeGraph()
	kg.AddURL("https://app.example.com", "")
	kg.AddVulnerability("app.example.com", "Candidate from graph")
	kg.AddVulnerability("app.example.com", "Confirmed finding")
	kg.AddVulnerability("app.example.com", "Informational finding")
	kg.AddVulnerability("app.example.com", "Disproven finding")

	if err := matrix.LogVulnerabilityWithStatus(matrix.GenerateVulnID("app.example.com", "Confirmed finding"), "app.example.com", "Confirmed finding", "poc", "yes", matrix.VulnerabilityStatusConfirmed, matrix.VulnerabilitySeverityHigh); err != nil {
		t.Fatalf("failed to log confirmed finding: %v", err)
	}
	if err := matrix.LogVulnerabilityWithStatus(matrix.GenerateVulnID("app.example.com", "Informational finding"), "app.example.com", "Informational finding", "poc", "no", matrix.VulnerabilityStatusInformational, matrix.VulnerabilitySeverityInformational); err != nil {
		t.Fatalf("failed to log informational finding: %v", err)
	}
	if err := matrix.LogVulnerabilityWithStatus(matrix.GenerateVulnID("app.example.com", "Disproven finding"), "app.example.com", "Disproven finding", "poc", "no", matrix.VulnerabilityStatusDisproven, matrix.VulnerabilitySeverityUnknown); err != nil {
		t.Fatalf("failed to log disproven finding: %v", err)
	}

	queue := collectHelperVulnQueue("app.example.com", kg)
	if len(queue) != 1 {
		t.Fatalf("expected exactly one unresolved candidate, got %#v", queue)
	}
	if queue[0].Finding != "Candidate from graph" {
		t.Fatalf("expected only unresolved candidate in queue, got %#v", queue)
	}
}

func TestBuildVulnerabilityReportInputFiltersByStatus(t *testing.T) {
	vulns := []matrix.VulnInfo{
		{TargetDomain: "app.example.com", Finding: "Confirmed SQL injection", Status: matrix.VulnerabilityStatusConfirmed, Severity: matrix.VulnerabilitySeverityHigh, DateTime: time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)},
		{TargetDomain: "app.example.com", Finding: "Candidate path traversal", Status: matrix.VulnerabilityStatusCandidate, Severity: matrix.VulnerabilitySeverityUnknown, DateTime: time.Date(2026, 7, 8, 1, 2, 4, 0, time.UTC)},
		{TargetDomain: "app.example.com", Finding: "Disproven XSS", Status: matrix.VulnerabilityStatusDisproven, Severity: matrix.VulnerabilitySeverityUnknown, DateTime: time.Date(2026, 7, 8, 1, 2, 5, 0, time.UTC)},
		{TargetDomain: "app.example.com", Finding: "Server header disclosed", Status: matrix.VulnerabilityStatusInformational, Severity: matrix.VulnerabilitySeverityInformational, DateTime: time.Date(2026, 7, 8, 1, 2, 6, 0, time.UTC)},
	}

	reportInput, informationalFindings := buildVulnerabilityReportInput(vulns)
	if !strings.Contains(reportInput, "Confirmed SQL injection") {
		t.Fatalf("expected confirmed finding in report input: %s", reportInput)
	}
	if strings.Contains(reportInput, "Candidate path traversal") {
		t.Fatalf("candidate finding leaked into report input: %s", reportInput)
	}
	if strings.Contains(reportInput, "Disproven XSS") {
		t.Fatalf("disproven finding leaked into report input: %s", reportInput)
	}
	if !strings.Contains(reportInput, "Server header disclosed") {
		t.Fatalf("expected informational finding in report input: %s", reportInput)
	}
	if len(informationalFindings) != 1 || informationalFindings[0].Finding != "Server header disclosed" {
		t.Fatalf("unexpected informational findings: %#v", informationalFindings)
	}
}

func TestAppendInformationalFindingsAlwaysAddsSection(t *testing.T) {
	report := appendInformationalFindings("# Report", nil)
	if !strings.Contains(report, "## Informational Findings") {
		t.Fatalf("expected informational section: %s", report)
	}
	if !strings.Contains(report, "No informational findings were recorded.") {
		t.Fatalf("expected empty informational message: %s", report)
	}

	report = appendInformationalFindings("# Report", []matrix.VulnInfo{{TargetDomain: "app.example.com", Finding: "Server header disclosed", Severity: matrix.VulnerabilitySeverityInformational}})
	if !strings.Contains(report, "- **app.example.com** [informational]: Server header disclosed") {
		t.Fatalf("expected informational finding: %s", report)
	}
}

func TestValidateVulnerabilityLogInput(t *testing.T) {
	err := validateVulnerabilityLogInput(
		"vid-1",
		"https://moneybird.com",
		"Exposed .env file containing sensitive credentials",
		"Leaked .env discovered and credentials parsed",
		"yes",
		matrix.VulnerabilityStatusConfirmed,
		matrix.VulnerabilitySeverityCritical,
	)
	if err == nil {
		t.Fatalf("expected credential-validation error for exploitable=yes without auth success evidence")
	}

	err = validateVulnerabilityLogInput(
		"vid-1",
		"https://moneybird.com",
		"Exposed .env file containing sensitive credentials",
		"Used leaked username/password to login; authenticated successfully and received HTTP 200",
		"yes",
		matrix.VulnerabilityStatusConfirmed,
		matrix.VulnerabilitySeverityCritical,
	)
	if err != nil {
		t.Fatalf("unexpected error for valid credential exploit evidence: %v", err)
	}

	err = validateVulnerabilityLogInput(
		"vid-2",
		"https://moneybird.com",
		"SQL Injection",
		"UNION-based injection returned database rows",
		"yes",
		matrix.VulnerabilityStatusConfirmed,
		matrix.VulnerabilitySeverityHigh,
	)
	if err != nil {
		t.Fatalf("unexpected error for non-credential finding: %v", err)
	}

	err = validateVulnerabilityLogInput(
		"vid-3",
		"https://moneybird.com",
		"Potential issue",
		"Test evidence",
		"no",
		matrix.VulnerabilityStatusCandidate,
		matrix.VulnerabilitySeverityUnknown,
	)
	if err == nil {
		t.Fatalf("expected error for candidate status")
	}

	err = validateVulnerabilityLogInput(
		"vid-4",
		"https://moneybird.com",
		"Server header disclosure",
		"HTTP response included Server header",
		"no",
		matrix.VulnerabilityStatusInformational,
		matrix.VulnerabilitySeverityHigh,
	)
	if err == nil {
		t.Fatalf("expected error for informational finding with non-informational severity")
	}
}

func TestDeriveDefaultTargetDomains(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   []string
	}{
		{
			name:   "subdomain target keeps exact host and wildcard",
			target: "https://app.example.com/login",
			want:   []string{"app.example.com", "*.app.example.com"},
		},
		{
			name:   "hostname without scheme",
			target: "api.internal.example.com",
			want:   []string{"api.internal.example.com", "*.api.internal.example.com"},
		},
		{
			name:   "ip target stays exact only",
			target: "10.0.0.15",
			want:   []string{"10.0.0.15"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveDefaultTargetDomains(tc.target)
			if len(got) != len(tc.want) {
				t.Fatalf("deriveDefaultTargetDomains(%q) len=%d want=%d (%v)", tc.target, len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("deriveDefaultTargetDomains(%q)[%d]=%q want %q", tc.target, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestScoreTool_HTTPRequestAllowedBeforeFirstExecution(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance}
	snapshot := matrix.KnowledgeSnapshot{TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	scored := scoreTool(def, target, snapshot, state)
	if scored.Score < 50 {
		t.Fatalf("expected initial http_request to remain highly ranked, got %d (%v)", scored.Score, scored.Reasons)
	}
}

func TestScoreTool_HTTPRequestBlockedWithoutNewIntelligence(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance}
	snapshot := matrix.KnowledgeSnapshot{TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	updateHTTPRequestGateState(state, target)
	scored := scoreTool(def, target, snapshot, state)
	if scored.Score >= 0 {
		t.Fatalf("expected http_request to be blocked without new intelligence, got %d (%v)", scored.Score, scored.Reasons)
	}
}

func TestScoreTool_HTTPRequestReenabledAfterNewIntelligence(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance}
	baseline := matrix.KnowledgeSnapshot{DiscoveredURLCount: 1, TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	updateHTTPRequestGateState(state, target)

	target.Vulnerabilities = append(target.Vulnerabilities, "interesting response behavior")
	updated := baseline
	updated.DiscoveredURLCount = 2
	scored := scoreTool(def, target, updated, state)
	if scored.Score < 0 {
		t.Fatalf("expected http_request to be reenabled after new intelligence, got %d (%v)", scored.Score, scored.Reasons)
	}
}

func TestScoreTool_HTTPRequestAllowsOneAuthReopenPerTargetState(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance, HTTPRequestGate: make(map[string]bool)}
	snapshot := matrix.KnowledgeSnapshot{TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	updateHTTPRequestGateState(state, target)
	target.Tokens = append(target.Tokens, "session=abc")

	scored := scoreTool(def, target, snapshot, state)
	if scored.Score < 0 {
		t.Fatalf("expected one auth-driven reopen, got %d (%v)", scored.Score, scored.Reasons)
	}

	target.HTTPRequestGate[authReopenGateKey(httpRequestTargetFingerprint(target), httpRequestAuthFingerprint(target))] = true
	updateHTTPRequestGateState(state, target)
	target.Tokens = append(target.Tokens, "session=def")
	scored = scoreTool(def, target, snapshot, state)
	if scored.Score >= 0 {
		t.Fatalf("expected repeated same-signal auth churn to stay blocked, got %d (%v)", scored.Score, scored.Reasons)
	}
}

func TestScoreTool_HTTPRequestAllowsMateriallyDifferentAuthState(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance, HTTPRequestGate: make(map[string]bool)}
	snapshot := matrix.KnowledgeSnapshot{TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	updateHTTPRequestGateState(state, target)
	target.Tokens = append(target.Tokens, "session=abc")
	first := scoreTool(def, target, snapshot, state)
	if first.Score < 0 {
		t.Fatalf("expected first auth state to reopen, got %d (%v)", first.Score, first.Reasons)
	}

	target.HTTPRequestGate[authReopenGateKey(httpRequestTargetFingerprint(target), httpRequestAuthFingerprint(target))] = true
	updateHTTPRequestGateState(state, target)
	target.Tokens = append(target.Tokens, "Authorization: Bearer token")
	second := scoreTool(def, target, snapshot, state)
	if second.Score < 0 {
		t.Fatalf("expected materially different auth state to reopen, got %d (%v)", second.Score, second.Reasons)
	}
}

func TestScoreTool_HTTPRequestIgnoresGlobalSnapshotNoise(t *testing.T) {
	def := matrix.ToolDefinition{Name: "decision_http_request", Technique: "http-request"}
	target := &matrix.Target{Value: "example.com", CurrentPhase: matrix.PhaseReconnaissance}
	baseline := matrix.KnowledgeSnapshot{DiscoveredURLCount: 1, TargetPhases: map[string]matrix.Phase{"example.com": matrix.PhaseReconnaissance}}
	state := &httpRequestGateState{}

	updateHTTPRequestGateState(state, target)

	noisy := baseline
	noisy.DiscoveredURLCount = 99
	noisy.VulnerabilityCount = 5
	noisy.TargetPhases["other.example.com"] = matrix.PhaseScanning

	scored := scoreTool(def, target, noisy, state)
	if scored.Score >= 0 {
		t.Fatalf("expected unrelated global changes to keep http_request blocked, got %d (%v)", scored.Score, scored.Reasons)
	}
}

func TestReachedIterationLimit(t *testing.T) {
	testCases := []struct {
		name        string
		globalIters int
		maxIters    int
		want        bool
	}{
		{name: "below limit", globalIters: 2, maxIters: 3, want: false},
		{name: "at limit", globalIters: 3, maxIters: 3, want: true},
		{name: "above limit", globalIters: 4, maxIters: 3, want: true},
		{name: "zero max treated as disabled", globalIters: 100, maxIters: 0, want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reachedIterationLimit(tc.globalIters, tc.maxIters)
			if got != tc.want {
				t.Fatalf("reachedIterationLimit(%d, %d) = %v, want %v", tc.globalIters, tc.maxIters, got, tc.want)
			}
		})
	}
}
