package core

import "testing"

func TestStatusFromEvidence(t *testing.T) {
	tests := []struct {
		name                string
		tier                EvidenceTier
		hasNegativeEvidence bool
		expected            string
	}{
		{name: "confirmed vulnerable", tier: EvidenceConfirmed, hasNegativeEvidence: false, expected: "vulnerable"},
		{name: "strong inconclusive", tier: EvidenceStrong, hasNegativeEvidence: false, expected: "inconclusive"},
		{name: "weak inconclusive", tier: EvidenceWeak, hasNegativeEvidence: false, expected: "inconclusive"},
		{name: "negative secure", tier: EvidenceConfirmed, hasNegativeEvidence: true, expected: "secure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusFromEvidence(tt.tier, tt.hasNegativeEvidence)
			if got != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestFormatEvidenceDetail(t *testing.T) {
	if got := formatEvidenceDetail(EvidenceStrong, "signal observed"); got != "[evidence:strong] signal observed" {
		t.Fatalf("unexpected detail format: %s", got)
	}
	if got := formatEvidenceDetail(EvidenceWeak, ""); got != "" {
		t.Fatalf("expected empty detail for empty summary, got %q", got)
	}
}

func TestMeetsThreshold(t *testing.T) {
	if !meetsThreshold(0.25, 0.20) {
		t.Fatalf("expected threshold to pass")
	}
	if meetsThreshold(0.19, 0.20) {
		t.Fatalf("expected threshold to fail")
	}
}
