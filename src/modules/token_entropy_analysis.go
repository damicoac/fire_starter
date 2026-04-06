package modules

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

// TokenEntropyAnalysisResult holds the result of the TokenEntropyAnalysis module execution.
type TokenEntropyAnalysisResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// TokenEntropyAnalysis executes the token_entropy_analysis security technique.
type TokenEntropyAnalysis struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []TokenEntropyAnalysisResult
	client     *http.Client
}

// NewTokenEntropyAnalysis creates a new instance of TokenEntropyAnalysis.
func NewTokenEntropyAnalysis(target string) *TokenEntropyAnalysis {
	return &TokenEntropyAnalysis{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 1,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *TokenEntropyAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func calcEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, char := range data {
		counts[char]++
	}
	entropy := 0.0
	length := float64(len(data))
	for _, count := range counts {
		prob := float64(count) / length
		entropy -= prob * math.Log2(prob)
	}
	return entropy
}

func (m *TokenEntropyAnalysis) Execute(ctx context.Context) ([]TokenEntropyAnalysisResult, error) {
	m.results = make([]TokenEntropyAnalysisResult, 0)

	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return m.results, err
	}
	defer resp.Body.Close()

	// Check cookies for low entropy
	for _, cookie := range resp.Cookies() {
		entropy := calcEntropy(cookie.Value)
		// Arbitrary low entropy threshold, and string > 5 chars to avoid tiny values like "1"
		if len(cookie.Value) > 5 && entropy < 2.5 {
			m.results = append(m.results, TokenEntropyAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Cookie %s has low entropy: %.2f", cookie.Name, entropy),
			})
		}
	}

	return m.results, nil
}
