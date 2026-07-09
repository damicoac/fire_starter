package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type MassAssignmentInjectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type MassAssignmentInjection struct {
	BaseModule
	Target  string
	results []MassAssignmentInjectionResult
}

func NewMassAssignmentInjection(target string) *MassAssignmentInjection {
	return &MassAssignmentInjection{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *MassAssignmentInjection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var assignmentPayloads = []map[string]interface{}{
	{"is_admin": true},
	{"isAdmin": true},
	{"role": "admin"},
	{"permissions": "all"},
	{"user": map[string]interface{}{"is_admin": true}},
}

const (
	massAssignmentRequestBudget = 24
	massAssignmentVerifyRetries = 2
)

var massAssignmentSeen sync.Map

func (m *MassAssignmentInjection) Execute(ctx context.Context) ([]MassAssignmentInjectionResult, error) {
	m.results = make([]MassAssignmentInjectionResult, 0)

	marker := fmt.Sprintf("firestarter_probe_%d", time.Now().UnixNano())
	baselinePayload := map[string]any{
		"username":           marker,
		"correlation_marker": marker,
		"display_name":       "firestarter",
	}

	baselineStatus, baselineBody, baselineErr := m.sendJSON(ctx, baselinePayload)
	if baselineErr != nil || baselineStatus < http.StatusOK || baselineStatus >= http.StatusMultipleChoices {
		return m.results, nil
	}

	controlPayload := map[string]any{
		"username":                  marker,
		"correlation_marker":        marker,
		"display_name":              "firestarter",
		"firestarter_probe_control": marker,
	}
	controlStatus, controlBody, controlErr := m.sendJSON(ctx, controlPayload)
	if controlErr != nil {
		return m.results, nil
	}

	echoesUnknownFields := controlStatus >= http.StatusOK && controlStatus < http.StatusMultipleChoices && strings.Contains(normalizedCompactLower(controlBody), "\"firestarter_probe_control\":\""+strings.ToLower(marker)+"\"")
	requestsUsed := 2
	foundExplicitNegativeEvidence := false
	sawReflectionOnlySignal := false
	bestTier := EvidenceWeak
	bestSummary := ""
	seenLocal := map[string]bool{}

	for _, payloadTemplate := range assignmentPayloads {
		if requestsUsed >= massAssignmentRequestBudget {
			break
		}

		mutantPayload := buildMutantPayload(marker, payloadTemplate)
		statusCode, responseBody, err := m.sendJSON(ctx, mutantPayload)
		requestsUsed++
		if err != nil {
			continue
		}
		if containsValidationRejection(responseBody) {
			continue
		}
		if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
			continue
		}

		verifyStatus, verifyBody, hasVerification := m.verifyPersistedState(ctx, marker, &requestsUsed)
		if !hasVerification {
			if hasPrivilegedFieldEcho(responseBody) || significantlyDiffersFromBaseline(baselineBody, responseBody) {
				bestTier, bestSummary = pickStrongerEvidence(bestTier, bestSummary, EvidenceWeak, "Mutation probe produced weak anomalous behavior but verification read could not be completed within retry/budget limits.")
			}
			continue
		}

		if verifyStatus < http.StatusOK || verifyStatus >= http.StatusMultipleChoices {
			if hasPrivilegedFieldEcho(responseBody) || significantlyDiffersFromBaseline(baselineBody, responseBody) {
				bestTier, bestSummary = pickStrongerEvidence(bestTier, bestSummary, EvidenceStrong, "Mutation probe produced differentiated behavior, but verification read was not successfully accessible.")
			}
			continue
		}

		if !strings.Contains(strings.ToLower(verifyBody), strings.ToLower(marker)) {
			persistedFields := privilegedFieldsPersisted(verifyBody, mutantPayload)
			if len(persistedFields) > 0 {
				for _, field := range persistedFields {
					dedupKey := m.Target + "|" + marker + "|" + field
					if seenLocal[dedupKey] {
						continue
					}
					if _, loaded := massAssignmentSeen.LoadOrStore(dedupKey, true); loaded {
						continue
					}
					seenLocal[dedupKey] = true
					summary := "Verified privileged field persistence in target object state on field " + field + "."
					detail := formatEvidenceDetail(EvidenceConfirmed, summary)
					m.Mu.Lock()
					m.RecordPoC(nil, nil, summary)
					m.results = append(m.results, MassAssignmentInjectionResult{
						Target: m.Target,
						Status: statusFromEvidence(EvidenceConfirmed, false),
						Detail: detail,
					})
					m.Mu.Unlock()
				}
				continue
			}
			if hasPrivilegedFieldEcho(responseBody) || significantlyDiffersFromBaseline(baselineBody, responseBody) {
				bestTier, bestSummary = pickStrongerEvidence(bestTier, bestSummary, EvidenceStrong, "Mutation probe changed response behavior, but verification read did not correlate to the target object marker.")
			}
			continue
		}

		persistedFields := privilegedFieldsPersisted(verifyBody, mutantPayload)
		if len(persistedFields) == 0 {
			hadAnomalousSignal := hasPrivilegedFieldEcho(responseBody) || echoesUnknownFields || significantlyDiffersFromBaseline(baselineBody, responseBody)
			if hadAnomalousSignal {
				foundExplicitNegativeEvidence = true
				if hasPrivilegedFieldEcho(responseBody) || echoesUnknownFields {
					sawReflectionOnlySignal = true
				}
				bestTier, bestSummary = pickStrongerEvidence(bestTier, bestSummary, EvidenceStrong, "Privileged fields were echoed or response shape changed, but verification read showed no privileged-field persistence for the correlated object.")
			}
			continue
		}

		for _, field := range persistedFields {
			dedupKey := m.Target + "|" + marker + "|" + field
			if seenLocal[dedupKey] {
				continue
			}
			if _, loaded := massAssignmentSeen.LoadOrStore(dedupKey, true); loaded {
				continue
			}
			seenLocal[dedupKey] = true

			summary := "Verified privileged field persistence for correlated object marker " + marker + " on field " + field + "."
			detail := formatEvidenceDetail(EvidenceConfirmed, summary)
			m.Mu.Lock()
			m.RecordPoC(nil, nil, summary)
			m.results = append(m.results, MassAssignmentInjectionResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceConfirmed, false),
				Detail: detail,
			})
			m.Mu.Unlock()
		}
	}

	if len(m.results) > 0 {
		return m.results, nil
	}

	if foundExplicitNegativeEvidence {
		if sawReflectionOnlySignal {
			summary := bestSummary
			if summary == "" {
				summary = "Reflection-like behavior was observed, but verification reads did not prove privileged-field persistence."
			}
			m.results = append(m.results, MassAssignmentInjectionResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceStrong, false),
				Detail: formatEvidenceDetail(EvidenceStrong, summary),
			})
			return m.results, nil
		}
		summary := "Verification reads for correlated objects did not show privileged-field persistence after mutation attempts."
		m.results = append(m.results, MassAssignmentInjectionResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, true),
			Detail: formatEvidenceDetail(EvidenceConfirmed, summary),
		})
		return m.results, nil
	}

	if bestSummary != "" {
		m.results = append(m.results, MassAssignmentInjectionResult{
			Target: m.Target,
			Status: statusFromEvidence(bestTier, false),
			Detail: formatEvidenceDetail(bestTier, bestSummary),
		})
	}

	return m.results, nil
}

func buildMutantPayload(marker string, payloadTemplate map[string]interface{}) map[string]any {
	mutantPayload := map[string]any{
		"username":           marker,
		"correlation_marker": marker,
	}
	for key, value := range payloadTemplate {
		if nested, ok := value.(map[string]interface{}); ok {
			clonedNested := map[string]any{}
			for nestedKey, nestedValue := range nested {
				clonedNested[nestedKey] = nestedValue
			}
			clonedNested["username"] = marker
			mutantPayload[key] = clonedNested
			continue
		}
		mutantPayload[key] = value
	}
	return mutantPayload
}

func pickStrongerEvidence(currentTier EvidenceTier, currentSummary string, candidateTier EvidenceTier, candidateSummary string) (EvidenceTier, string) {
	if currentSummary == "" {
		return candidateTier, candidateSummary
	}
	if evidenceStrength(candidateTier) > evidenceStrength(currentTier) {
		return candidateTier, candidateSummary
	}
	return currentTier, currentSummary
}

func evidenceStrength(tier EvidenceTier) int {
	switch tier {
	case EvidenceConfirmed:
		return 3
	case EvidenceStrong:
		return 2
	default:
		return 1
	}
}

func (m *MassAssignmentInjection) verifyPersistedState(ctx context.Context, marker string, requestsUsed *int) (int, string, bool) {
	for attempt := 0; attempt < massAssignmentVerifyRetries; attempt++ {
		if *requestsUsed >= massAssignmentRequestBudget {
			return 0, "", false
		}

		statusCode, responseBody, err := m.sendVerificationRead(ctx, marker)
		*requestsUsed++
		if err == nil {
			return statusCode, responseBody, true
		}

		if attempt+1 < massAssignmentVerifyRetries {
			timer := time.NewTimer(150 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return 0, "", false
			case <-timer.C:
			}
		}
	}
	return 0, "", false
}

func (m *MassAssignmentInjection) sendVerificationRead(ctx context.Context, marker string) (int, string, error) {
	targetURL, err := url.Parse(m.Target)
	if err != nil {
		return 0, "", err
	}

	query := targetURL.Query()
	query.Set("firestarter_probe_marker", marker)
	targetURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), bytes.NewBuffer(nil))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody), nil
}

func (m *MassAssignmentInjection) sendJSON(ctx context.Context, payload map[string]any) (int, string, error) {
	bodyBytes, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return 0, "", marshalErr
	}

	req, err := http.NewRequestWithContext(ctx, "POST", m.Target, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody), nil
}

func hasPrivilegedFieldEcho(responseBody string) bool {
	normalized := normalizedCompactLower(responseBody)
	indicators := []string{
		"\"is_admin\":true",
		"\"isadmin\":true",
		"\"role\":\"admin\"",
		"\"permissions\":\"all\"",
	}
	for _, indicator := range indicators {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}
	return false
}

func privilegedFieldsPersisted(responseBody string, mutantPayload map[string]any) []string {
	normalized := normalizedCompactLower(responseBody)
	persisted := make([]string, 0)
	seen := map[string]bool{}

	addIfPersisted := func(field string, indicators []string) {
		if seen[field] {
			return
		}
		for _, indicator := range indicators {
			if strings.Contains(normalized, indicator) {
				persisted = append(persisted, field)
				seen[field] = true
				return
			}
		}
	}

	if value, ok := mutantPayload["is_admin"].(bool); ok && value {
		addIfPersisted("is_admin", []string{"\"is_admin\":true"})
	}
	if value, ok := mutantPayload["isAdmin"].(bool); ok && value {
		addIfPersisted("isAdmin", []string{"\"isadmin\":true", "\"is_admin\":true"})
	}
	if value, ok := mutantPayload["role"].(string); ok && strings.EqualFold(value, "admin") {
		addIfPersisted("role", []string{"\"role\":\"admin\""})
	}
	if value, ok := mutantPayload["permissions"].(string); ok && strings.EqualFold(value, "all") {
		addIfPersisted("permissions", []string{"\"permissions\":\"all\""})
	}
	if userObj, ok := mutantPayload["user"].(map[string]any); ok {
		if value, ok := userObj["is_admin"].(bool); ok && value {
			addIfPersisted("user.is_admin", []string{"\"is_admin\":true"})
		}
	}

	return persisted
}

func containsValidationRejection(responseBody string) bool {
	rejectionTokens := []string{"invalid", "forbidden", "denied", "unauthorized", "not allowed", "validation"}
	return containsAnyToken(responseBody, rejectionTokens)
}

func significantlyDiffersFromBaseline(baselineBody string, responseBody string) bool {
	baselineLen := len(baselineBody)
	responseLen := len(responseBody)
	diff := baselineLen - responseLen
	if diff < 0 {
		diff = -diff
	}
	return meetsThreshold(safeRatio(diff, baselineLen+1), 0.1) || diff > 100
}

func init() {
	RegisterModule("mass_assignment_injection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting MassAssignmentInjection on: %s", target))

		tester := NewMassAssignmentInjection(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
