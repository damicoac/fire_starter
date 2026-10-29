package core

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
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

// calcEntropy computes Shannon entropy over runes so that multi-byte
// characters are not mixed with a byte-based length (which would
// systematically underestimate entropy).
func calcEntropy(data string) float64 {
	length := utf8.RuneCountInString(data)
	if length == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, char := range data {
		counts[char]++
	}
	entropy := 0.0
	for _, count := range counts {
		prob := float64(count) / float64(length)
		entropy -= prob * math.Log2(prob)
	}
	return entropy
}

// sessionLikeCookie reports whether the cookie name looks session- or
// authentication-related; only those carry token entropy worth judging.
func sessionLikeCookie(name string) bool {
	lower := strings.ToLower(name)
	markers := []string{"session", "auth", "token", "sid", "remember", "jwt"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		entropy := calcEntropy(cookie.Value)
		// Gate on session-like names, a realistic token length and a
		// meaningful threshold so benign cookies (consent flags, short ids,
		// ordinary words) are not flagged as weak tokens.
		if sessionLikeCookie(cookie.Name) && len(cookie.Value) >= 16 && entropy < 3.0 {
			detail := fmt.Sprintf("Cookie %s has low entropy: %.2f", cookie.Name, entropy)
			m.RecordPoC(req, nil, detail)
			m.results = append(m.results, TokenEntropyAnalysisResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, false),
				Detail: detail,
			})
		}
	}

	if len(cookies) == 0 {
		m.addResult("No cookies observed in response; token entropy not assessable", statusFromEvidence(EvidenceWeak, false))
	} else if len(m.results) == 0 {
		m.addResult(fmt.Sprintf("%d cookies observed; no low-entropy session cookies detected", len(cookies)), statusFromEvidence(EvidenceConfirmed, true))
	}

	return m.results, nil
}

func (m *TokenEntropyAnalysis) addResult(detail, status string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.RecordPoC(nil, nil, detail)
	m.results = append(m.results, TokenEntropyAnalysisResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
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
