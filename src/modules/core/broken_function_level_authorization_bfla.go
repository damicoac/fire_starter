package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BrokenFunctionLevelAuthorizationBflaResult holds the result of the BrokenFunctionLevelAuthorizationBfla module execution.
type BrokenFunctionLevelAuthorizationBflaResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// BrokenFunctionLevelAuthorizationBfla executes the broken_function_level_authorization_bfla security technique.
type BrokenFunctionLevelAuthorizationBfla struct {
	Target string
	BaseModule
	results []BrokenFunctionLevelAuthorizationBflaResult

	// probe counters; guarded by Mu, read only after all workers finish.
	testedCount  int
	successCount int
	probeErrors  int
}

// NewBrokenFunctionLevelAuthorizationBfla creates a new instance.
func NewBrokenFunctionLevelAuthorizationBfla(target string) *BrokenFunctionLevelAuthorizationBfla {
	return &BrokenFunctionLevelAuthorizationBfla{
		Target: EnsureHTTPPrefix(target),
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
	}
}

func (m *BrokenFunctionLevelAuthorizationBfla) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var adminPaths = []string{
	"/admin",
	"/api/admin",
	"/api/v1/admin",
	"/administrator",
	"/manage",
	"/config",
}

// authzAdminContentMarkers reports whether a lowercase body carries
// administrative-console content, required before generic slugs such as
// /manage or /config count as exposed admin functions.
func authzAdminContentMarkers(bodyLower string) bool {
	return containsAnyToken(bodyLower, []string{
		"admin", "administrator", "dashboard", "control panel", "management",
	})
}

func (m *BrokenFunctionLevelAuthorizationBfla) getBaselineLength(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target+"/nonexistent_admin_path_12345", nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return 0, err
	}
	return len(body), nil
}

func (m *BrokenFunctionLevelAuthorizationBfla) Execute(ctx context.Context) ([]BrokenFunctionLevelAuthorizationBflaResult, error) {
	m.results = make([]BrokenFunctionLevelAuthorizationBflaResult, 0)
	m.testedCount = 0
	m.successCount = 0
	m.probeErrors = 0

	baselineLen, err := m.getBaselineLength(ctx)
	if err != nil {
		m.results = append(m.results, BrokenFunctionLevelAuthorizationBflaResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Unable to establish response-length baseline: "+err.Error()),
		})
		return m.results, nil
	}
	if baselineLen <= 0 {
		// A zero-length baseline makes the length-differential judge fire on
		// any non-empty 200; skip judging entirely rather than risk a false
		// positive.
		m.results = append(m.results, BrokenFunctionLevelAuthorizationBflaResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline response body is empty; length-differential judging is unreliable."),
		})
		return m.results, nil
	}

	jobs := make(chan string, len(adminPaths))
	for _, p := range adminPaths {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPath(ctx, path, baselineLen)
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if len(m.results) == 0 {
			// After probing ran, an empty result set is inconclusive — not a
			// clean scan — regardless of how many paths returned HTTP 200: the
			// gates may have suppressed every response without confirming
			// anything.
			detail := fmt.Sprintf("Probing completed with no BFLA finding (%d paths probed, %d returned HTTP 200, %d transport errors); no exposed administrative function was confirmed.", m.testedCount, m.successCount, m.probeErrors)
			m.results = append(m.results, BrokenFunctionLevelAuthorizationBflaResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: formatEvidenceDetail(EvidenceWeak, detail),
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *BrokenFunctionLevelAuthorizationBfla) testPath(ctx context.Context, path string, baselineLen int) {
	m.Mu.Lock()
	m.testedCount++
	m.Mu.Unlock()

	testURL := m.Target + path

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}
	defer resp.Body.Close()
	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.Mu.Lock()
		m.probeErrors++
		m.Mu.Unlock()
		return
	}

	// If we get a 200 OK on an admin endpoint, ensure it's not a false positive
	if resp.StatusCode != http.StatusOK {
		return
	}
	m.Mu.Lock()
	m.successCount++
	m.Mu.Unlock()

	bodyLower := strings.ToLower(string(bodyBytes))
	// Skip login walls and 200-wrapped error envelopes before the
	// length-only judge runs.
	if authzLoginWallDetected(bodyLower) || authzErrorEnvelope(bodyLower) {
		return
	}
	// Generic slugs (/manage, /config) exist on countless unprivileged pages;
	// require actual administrative content before flagging them.
	if (path == "/manage" || path == "/config") && !authzAdminContentMarkers(bodyLower) {
		return
	}

	diff := len(bodyBytes) - baselineLen
	if diff < 0 {
		diff = -diff
	}

	isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500

	if isSignificantlyDifferent {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Unauthenticated access to administrative endpoint: "+testURL)
		m.results = append(m.results, BrokenFunctionLevelAuthorizationBflaResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Unauthenticated access to administrative endpoint: " + testURL,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("broken_function_level_authorization_bfla", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting BrokenFunctionLevelAuthorizationBfla on: %s", target))

		tester := NewBrokenFunctionLevelAuthorizationBfla(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
