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

func (m *IDORManipulation) getBaselineBody(ctx context.Context, u *url.URL) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return "", err
	}
	return string(body), nil
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

	baselineBody, err := m.getBaselineBody(ctx, parsedURL)
	if err != nil {
		m.results = append(m.results, IDORManipulationResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Unable to establish response-length baseline: "+err.Error()),
		})
		return m.results, nil
	}
	baselineLen := len(baselineBody)
	baselineNorm := normalizedCompactLower(baselineBody)
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
					m.testPayload(ctx, parsedURL, payload, baselineNorm)
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

// idorValidationNoise are response fragments that describe an invalid lookup
// (validation noise) rather than an object representation; they veto the
// differential judge.
var idorValidationNoise = []string{
	"invalid id", "record not found", "not found", "does not exist", "no such",
}

func (m *IDORManipulation) testPayload(ctx context.Context, u *url.URL, payload string, baselineNorm string) {
	m.Mu.Lock()
	m.testedCount++
	m.Mu.Unlock()

	query := u.Query()
	testURL := *u
	hasIDKey := false
	if len(query) > 0 {
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
	// Gate the differential judge: skip auth walls, 200-wrapped error
	// envelopes, validation-noise lookups, and bodies without positive
	// object markers.
	if authzLoginWallDetected(bodyLower) || authzErrorEnvelope(bodyLower) ||
		!authzPositiveObjectMarkers(bodyLower) || containsAnyToken(bodyLower, idorValidationNoise) {
		return
	}

	if !hasIDKey {
		// Fallback dual-injection (arbitrary canonical parameters added to a
		// URL that addresses no object) can only ever produce length-only
		// noise: drop length-only judgments from it entirely.
		return
	}

	// Normalized-body differential: the probe body must differ from the
	// baseline after whitespace-insensitive normalization. A length-only
	// judge was dropped — dynamic content (timestamps, nonces) made it fire
	// on every volatile response.
	normProbe := normalizedCompactLower(string(bodyBytes))
	if normProbe == baselineNorm {
		return
	}

	// Reproduce the differential with a second request carrying a different
	// mutated value: genuine object access reproduces across ID values; a
	// one-off validation artifact does not.
	confirmPayload := ""
	for _, candidate := range idorIds {
		if candidate != payload {
			confirmPayload = candidate
			break
		}
	}
	if !m.idorDifferentialReproduced(ctx, u, confirmPayload, baselineNorm) {
		return
	}

	m.Mu.Lock()
	m.RecordPoC(req, nil, "Potential IDOR found. Reached object with ID "+payload+" at "+testURL.String())
	m.results = append(m.results, IDORManipulationResult{
		Target: m.Target,
		Status: "vulnerable",
		Detail: "Potential IDOR found. Reached object with ID " + payload + " at " + testURL.String() + " (differential reproduced with a different mutated value)",
	})
	m.Mu.Unlock()
}

// idorDifferentialReproduced re-issues the probe with a different mutated ID
// value and reports whether the normalized-body differential against the
// baseline reproduces (and the response passes the same gates).
func (m *IDORManipulation) idorDifferentialReproduced(ctx context.Context, u *url.URL, confirmPayload, baselineNorm string) bool {
	query := u.Query()
	for _, key := range idorIDKeys {
		if _, ok := query[key]; ok {
			query.Set(key, confirmPayload)
		}
	}
	confirmURL := *u
	confirmURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", confirmURL.String(), nil)
	if err != nil {
		return false
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	bodyLower := strings.ToLower(string(body))
	if authzLoginWallDetected(bodyLower) || authzErrorEnvelope(bodyLower) ||
		!authzPositiveObjectMarkers(bodyLower) || containsAnyToken(bodyLower, idorValidationNoise) {
		return false
	}
	return normalizedCompactLower(string(body)) != baselineNorm
}

func init() {
	RegisterModule("idor_manipulation", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
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
