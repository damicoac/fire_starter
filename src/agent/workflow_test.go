package agent

import "testing"

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

func TestValidateVulnerabilityLogInput(t *testing.T) {
	err := validateVulnerabilityLogInput(
		"vid-1",
		"https://moneybird.com",
		"Exposed .env file containing sensitive credentials",
		"Leaked .env discovered and credentials parsed",
		"yes",
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
	)
	if err != nil {
		t.Fatalf("unexpected error for non-credential finding: %v", err)
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
