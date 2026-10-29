package core

import "strings"

type EvidenceTier string

const (
	EvidenceConfirmed EvidenceTier = "confirmed"
	EvidenceStrong    EvidenceTier = "strong"
	EvidenceWeak      EvidenceTier = "weak"
)

func normalizedCompactLower(input string) string {
	compact := strings.ToLower(input)
	compact = strings.ReplaceAll(compact, " ", "")
	compact = strings.ReplaceAll(compact, "\n", "")
	compact = strings.ReplaceAll(compact, "\t", "")
	return compact
}

func containsAnyToken(input string, tokens []string) bool {
	lower := strings.ToLower(input)
	for _, token := range tokens {
		if strings.Contains(lower, strings.ToLower(token)) {
			return true
		}
	}
	return false
}

func safeRatio(numerator int, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func meetsThreshold(value float64, threshold float64) bool {
	return value >= threshold
}

// statusFromEvidence maps an evidence tier and negative signal to a status.
// A negative signal only yields "secure" when it is confirmed
// (EvidenceConfirmed); weaker tiers with a negative signal remain
// "inconclusive" because the evidence cannot rule out a false negative.
func statusFromEvidence(tier EvidenceTier, hasConfirmingNegative bool) string {
	if hasConfirmingNegative {
		if tier == EvidenceConfirmed {
			return "secure"
		}
		return "inconclusive"
	}
	if tier == EvidenceConfirmed {
		return "vulnerable"
	}
	return "inconclusive"
}

func formatEvidenceDetail(tier EvidenceTier, summary string) string {
	if summary == "" {
		return ""
	}
	return "[evidence:" + string(tier) + "] " + summary
}

// EvaluateDifferentialEvidence compares responses from true and false conditions against a baseline.
// Bodies are normalized (lowercased, whitespace-stripped) so volatile tokens such as
// CSRF fields or timestamps do not force every comparison to diverge.
// Returns EvidenceConfirmed if one condition matches the baseline while the other diverges.
// If no baseline is available (hasBaseline == false), returns EvidenceStrong when the
// conditions differ. An empty baseline body with hasBaseline == true is a real
// (empty) baseline, not a missing one. Otherwise returns EvidenceWeak.
func EvaluateDifferentialEvidence(trueBody, falseBody, baseBody string, hasBaseline bool) EvidenceTier {
	trueNorm := normalizedCompactLower(trueBody)
	falseNorm := normalizedCompactLower(falseBody)
	if trueNorm == "" || falseNorm == "" {
		return EvidenceWeak
	}
	if trueNorm == falseNorm {
		return EvidenceWeak
	}
	if hasBaseline {
		baseNorm := normalizedCompactLower(baseBody)
		if (trueNorm == baseNorm && falseNorm != baseNorm) || (trueNorm != baseNorm && falseNorm == baseNorm) {
			return EvidenceConfirmed
		}
		// If both conditions differ from baseline, page responses may be volatile/dynamic
		return EvidenceWeak
	}
	return EvidenceStrong
}
