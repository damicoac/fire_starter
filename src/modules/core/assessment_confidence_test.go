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
		{name: "strong negative inconclusive", tier: EvidenceStrong, hasNegativeEvidence: true, expected: "inconclusive"},
		{name: "weak negative inconclusive", tier: EvidenceWeak, hasNegativeEvidence: true, expected: "inconclusive"},
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

func TestEvaluateDifferentialEvidence(t *testing.T) {
	// Case 1: identical true and false bodies -> Weak
	if got := EvaluateDifferentialEvidence("same", "same", "base", true); got != EvidenceWeak {
		t.Fatalf("expected EvidenceWeak for identical bodies, got %s", got)
	}

	// Case 2: true matches base, false differs -> Confirmed
	if got := EvaluateDifferentialEvidence("base", "differ", "base", true); got != EvidenceConfirmed {
		t.Fatalf("expected EvidenceConfirmed, got %s", got)
	}

	// Case 3: true differs, false matches base -> Confirmed
	if got := EvaluateDifferentialEvidence("differ", "base", "base", true); got != EvidenceConfirmed {
		t.Fatalf("expected EvidenceConfirmed, got %s", got)
	}

	// Case 4: true differs from false and both differ from baseline -> Weak (dynamic page protection)
	if got := EvaluateDifferentialEvidence("differ1", "differ2", "base", true); got != EvidenceWeak {
		t.Fatalf("expected EvidenceWeak for volatile baseline mismatch, got %s", got)
	}

	// Case 5: no baseline available but true differs from false -> Strong
	if got := EvaluateDifferentialEvidence("differ1", "differ2", "", false); got != EvidenceStrong {
		t.Fatalf("expected EvidenceStrong without baseline, got %s", got)
	}

	// Case 6: empty bodies -> Weak
	if got := EvaluateDifferentialEvidence("", "", "", true); got != EvidenceWeak {
		t.Fatalf("expected EvidenceWeak for empty bodies, got %s", got)
	}

	// Case 7: empty baseline body counts as a real baseline, not a missing one
	if got := EvaluateDifferentialEvidence("", "nonempty", "", true); got != EvidenceWeak {
		t.Fatalf("expected EvidenceWeak for empty true body against empty baseline, got %s", got)
	}

	// Case 8: normalization makes whitespace/case-only differences equal
	// (true matches baseline despite formatting, false differs -> Confirmed)
	if got := EvaluateDifferentialEvidence("Hello  World\n", "different", "hello world", true); got != EvidenceConfirmed {
		t.Fatalf("expected EvidenceConfirmed after normalization, got %s", got)
	}

	// Case 9: differing only in whitespace/case between true and false -> Weak
	if got := EvaluateDifferentialEvidence("Hello  World\n", "hello world", "other", true); got != EvidenceWeak {
		t.Fatalf("expected EvidenceWeak for normalization-equal bodies, got %s", got)
	}
}
