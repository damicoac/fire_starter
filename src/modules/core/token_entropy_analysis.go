package core

import (
	"context"
	"fmt"
	"math"
	"net/http"
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
	BaseModule
	Target  string
	results []TokenEntropyAnalysisResult
}

// NewTokenEntropyAnalysis creates a new instance of TokenEntropyAnalysis.
func NewTokenEntropyAnalysis(target string) *TokenEntropyAnalysis {
	return &TokenEntropyAnalysis{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *TokenEntropyAnalysis) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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

	resp, err := m.Client.Do(req)
	if err != nil {
		return m.results, err
	}
	defer resp.Body.Close()

	// Check cookies for low entropy
	for _, cookie := range resp.Cookies() {
		entropy := calcEntropy(cookie.Value)
		// Arbitrary low entropy threshold, and string > 5 chars to avoid tiny values like "1"
		if len(cookie.Value) > 5 && entropy < 2.5 {
			m.RecordPoC(req, nil, fmt.Sprintf("Cookie %s has low entropy: %.2f", cookie.Name, entropy))
			m.results = append(m.results, TokenEntropyAnalysisResult{
				Target: m.Target,
				Status: "vulnerable",
				Detail: fmt.Sprintf("Cookie %s has low entropy: %.2f", cookie.Name, entropy),
			})
		}
	}

	return m.results, nil
}

func init() {
	RegisterModule("token_entropy_analysis", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting TokenEntropyAnalysis on: %s", target))

		tester := NewTokenEntropyAnalysis(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
