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
