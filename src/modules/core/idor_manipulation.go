package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IDORManipulationResult holds the result of the IDORManipulation module execution.
type IDORManipulationResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// IDORManipulation executes the idor_manipulation security technique.
type IDORManipulation struct {
	BaseModule
	Target  string
	results []IDORManipulationResult

	// probe counters; guarded by Mu, read only after all workers finish.
	testedCount  int
	successCount int
	probeErrors  int
}

// NewIDORManipulation creates a new instance.
func NewIDORManipulation(target string) *IDORManipulation {
	return &IDORManipulation{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *IDORManipulation) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *IDORManipulation) getBaselineLength(ctx context.Context, u *url.URL) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
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

// idorIds are ID-shaped replacement values. Role names such as "admin" are
// deliberately excluded: they produce validation noise, not object access.
var idorIds = []string{"1", "0", "2", "1000", "9999999999"}

// idorIDKeys lists query-parameter names that actually address objects.
// Overwriting every parameter destroys pagination/filter context and makes
// ordinary parameter changes look like IDOR differentials.
var idorIDKeys = []string{
	"id", "user_id", "uid", "account_id", "order_id", "customer_id",
	"doc_id", "record_id", "item_id", "invoice_id", "profile_id",
	"message_id", "file_id", "object_id", "post_id", "comment_id",
	"transaction_id", "ref_id",
}

func (m *IDORManipulation) Execute(ctx context.Context) ([]IDORManipulationResult, error) {
	m.results = make([]IDORManipulationResult, 0)
	m.testedCount = 0
	m.successCount = 0
	m.probeErrors = 0

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	baselineLen, err := m.getBaselineLength(ctx, parsedURL)
	if err != nil {
		m.results = append(m.results, IDORManipulationResult{
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
		m.results = append(m.results, IDORManipulationResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline response body is empty; length-differential judging is unreliable."),
		})
		return m.results, nil
	}

	jobs := make(chan string, len(idorIds))
	for _, p := range idorIds {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, parsedURL, payload, baselineLen)
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
			// clean scan — regardless of how many requests returned HTTP 200:
			// the gates may have suppressed every response without confirming
			// anything.
			detail := fmt.Sprintf("Probing completed with no IDOR finding (%d probes, %d returned HTTP 200, %d transport errors); no out-of-bounds object access was confirmed.", m.testedCount, m.successCount, m.probeErrors)
			m.results = append(m.results, IDORManipulationResult{
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

func (m *IDORManipulation) testPayload(ctx context.Context, u *url.URL, payload string, baselineLen int) {
	m.Mu.Lock()
	m.testedCount++
	m.Mu.Unlock()

	query := u.Query()
	testURL := *u
	if len(query) > 0 {
		hasIDKey := false
		for _, key := range idorIDKeys {
			if _, ok := query[key]; ok {
				hasIDKey = true
				query.Set(key, payload)
			}
		}
		if hasIDKey {
			testURL.RawQuery = query.Encode()
		} else {
			// No ID-like parameter: fall back to adding canonical ID
			// parameters and leave every existing parameter untouched.
			query.Add("user_id", payload)
			query.Add("account_id", payload)
			testURL.RawQuery = query.Encode()
		}
	} else {
		query.Add("user_id", payload)
		query.Add("account_id", payload)
		testURL.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
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

	if resp.StatusCode != http.StatusOK {
		return
	}
	m.Mu.Lock()
	m.successCount++
	m.Mu.Unlock()

	bodyLower := strings.ToLower(string(bodyBytes))
	// Gate the length-only judge: skip auth walls, 200-wrapped error
	// envelopes, and bodies without positive object markers.
	if authzLoginWallDetected(bodyLower) || authzErrorEnvelope(bodyLower) ||
		!authzPositiveObjectMarkers(bodyLower) || strings.Contains(bodyLower, "invalid id") {
		return
	}

	// Differential analysis: does it differ significantly from the baseline?
	diff := len(bodyBytes) - baselineLen
	if diff < 0 {
		diff = -diff
	}

	// If difference is > 10% or > 500 bytes, consider it an IDOR
	isSignificantlyDifferent := float64(diff)/float64(baselineLen+1) > 0.1 || diff > 500

	if isSignificantlyDifferent {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Potential IDOR found. Reached object with ID "+payload+" at "+testURL.String())
		m.results = append(m.results, IDORManipulationResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Potential IDOR found. Reached object with ID " + payload + " at " + testURL.String(),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("idor_manipulation", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting IDORManipulation on: %s", target))

		tester := NewIDORManipulation(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
