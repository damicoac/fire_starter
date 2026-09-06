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

func statusFromEvidence(tier EvidenceTier, hasNegativeEvidence bool) string {
	if hasNegativeEvidence {
		return "secure"
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
// Returns EvidenceConfirmed if one condition matches the baseline while the other diverges.
// If no baseline is available, returns EvidenceStrong if trueBody != falseBody.
// Otherwise returns EvidenceWeak.
func EvaluateDifferentialEvidence(trueBody, falseBody, baseBody string) EvidenceTier {
	if trueBody == "" || falseBody == "" {
		return EvidenceWeak
	}
	if trueBody == falseBody {
		return EvidenceWeak
	}
	if baseBody != "" {
		if (trueBody == baseBody && falseBody != baseBody) || (trueBody != baseBody && falseBody == baseBody) {
			return EvidenceConfirmed
		}
		// If both conditions differ from baseline, page responses may be volatile/dynamic
		return EvidenceWeak
	}
	return EvidenceStrong
}
