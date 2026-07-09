package core

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type RateLimitProbingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type RateLimitProbing struct {
	BaseModule
	Target  string
	results []RateLimitProbingResult
}

func NewRateLimitProbing(target string) *RateLimitProbing {
	return &RateLimitProbing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *RateLimitProbing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

const (
	rateLimitBurstRequests    = 50
	rateLimitRecoveryRequests = 12
	rateLimitRecoveryPause    = 200 * time.Millisecond
)

type rateProbeSnapshot struct {
	requestsDone       int
	successCount       int
	firstHalfSuccess   int
	secondHalfSuccess  int
	status4xxCount     int
	status5xxCount     int
	got429             bool
	gotRetryAfter      bool
	gotAuthChallenge   bool
	recoveryDone       int
	recoverySuccess    int
	recovery429        bool
	recoveryRetryAfter bool
	lastReq            *http.Request
}

func (m *RateLimitProbing) Execute(ctx context.Context) ([]RateLimitProbingResult, error) {
	m.results = make([]RateLimitProbingResult, 0)

	baselineReq, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return m.results, nil
	}

	baselineStatus := 0
	baselineResp, err := m.Client.Do(baselineReq)
	if err == nil {
		baselineStatus = baselineResp.StatusCode
		baselineResp.Body.Close()
	}

	if baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden {
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Baseline endpoint is auth-gated (401/403), so unauthenticated rate-limit probing is inconclusive."),
		})
		return m.results, nil
	}

	burstSnapshot, done, err := m.runBurstPhase(ctx)
	if err != nil {
		return m.results, err
	}
	if !done {
		return m.results, nil
	}

	recoverySnapshot := m.runRecoveryPhase(ctx)

	burstSuccessRate := safeRatio(burstSnapshot.successCount, burstSnapshot.requestsDone)
	firstHalfRate := safeRatio(burstSnapshot.firstHalfSuccess, rateLimitBurstRequests/2)
	secondHalfRate := safeRatio(burstSnapshot.secondHalfSuccess, rateLimitBurstRequests/2)
	recoveryRate := safeRatio(recoverySnapshot.recoverySuccess, recoverySnapshot.recoveryDone)

	hasBurstDegradation := meetsThreshold(firstHalfRate-secondHalfRate, 0.2)
	hasRecoveryNormalization := recoverySnapshot.recoveryDone >= rateLimitRecoveryRequests/2 && recoveryRate > secondHalfRate+0.2
	hasMeaningfulThrottleSignal := burstSnapshot.got429 || burstSnapshot.gotRetryAfter
	hasCorroboratedThrottle := hasMeaningfulThrottleSignal && hasBurstDegradation && (hasRecoveryNormalization || recoverySnapshot.recovery429 || recoverySnapshot.recoveryRetryAfter)
	hasContradictorySignals := hasMeaningfulThrottleSignal && !hasBurstDegradation && burstSuccessRate > 0.75

	switch {
	case burstSnapshot.gotAuthChallenge:
		m.RecordPoC(burstSnapshot.lastReq, nil, "Auth challenge appeared during burst probing; unable to isolate pure rate-limit behavior.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Authentication controls appeared during probing, making rate-limit attribution inconclusive."),
		})
	case burstSnapshot.requestsDone < rateLimitBurstRequests/2 || burstSuccessRate < 0.35:
		m.RecordPoC(burstSnapshot.lastReq, nil, "Burst probing had unstable responses and did not provide reproducible throughput signals.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, "Burst phase was too unstable for reliable classification."),
		})
	case hasCorroboratedThrottle:
		m.RecordPoC(burstSnapshot.lastReq, nil, "Corroborated throttling behavior detected across burst and recovery phases.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, true),
			Detail: formatEvidenceDetail(EvidenceConfirmed, "Corroborated rate limiting observed via throttling indicators, burst degradation, and recovery-phase normalization."),
		})
	case hasContradictorySignals:
		m.RecordPoC(burstSnapshot.lastReq, nil, "Partial throttling indicators were observed without corroborated burst degradation.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "Partial throttling indicators were present, but supporting temporal/recovery signals were contradictory."),
		})
	case !hasMeaningfulThrottleSignal && !hasBurstDegradation && burstSuccessRate >= 0.8 && recoveryRate >= 0.8:
		m.RecordPoC(burstSnapshot.lastReq, nil, "High request success remained stable across burst and recovery phases with no throttling evidence.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: formatEvidenceDetail(EvidenceConfirmed, "No meaningful throttling indicators were observed during burst or recovery phases."),
		})
	default:
		m.RecordPoC(burstSnapshot.lastReq, nil, "Rate-limit probe produced partial or mixed signals that could not be causally corroborated.")
		m.results = append(m.results, RateLimitProbingResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceStrong, false),
			Detail: formatEvidenceDetail(EvidenceStrong, "Burst/recovery phases produced mixed indicators, so result is inconclusive."),
		})
	}

	return m.results, nil
}

func (m *RateLimitProbing) runBurstPhase(ctx context.Context) (rateProbeSnapshot, bool, error) {
	snapshot := rateProbeSnapshot{}
	jobs := make(chan int, rateLimitBurstRequests)
	for i := 0; i < rateLimitBurstRequests; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					req, reqErr := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
					if reqErr != nil {
						continue
					}
					resp, doErr := m.Client.Do(req)
					if doErr != nil {
						continue
					}
					statusCode := resp.StatusCode
					retryAfter := resp.Header.Get("Retry-After") != ""
					resp.Body.Close()

					m.Mu.Lock()
					snapshot.requestsDone++
					snapshot.lastReq = req
					if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
						snapshot.successCount++
						if idx < rateLimitBurstRequests/2 {
							snapshot.firstHalfSuccess++
						} else {
							snapshot.secondHalfSuccess++
						}
					}
					if statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError {
						snapshot.status4xxCount++
					}
					if statusCode >= http.StatusInternalServerError {
						snapshot.status5xxCount++
					}
					if statusCode == http.StatusTooManyRequests {
						snapshot.got429 = true
					}
					if retryAfter {
						snapshot.gotRetryAfter = true
					}
					if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
						snapshot.gotAuthChallenge = true
					}
					m.Mu.Unlock()
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
		m.Mu.Lock()
		captured := snapshot
		m.Mu.Unlock()
		return captured, true, nil
	case <-ctx.Done():
		<-done
		m.Mu.Lock()
		captured := snapshot
		m.Mu.Unlock()
		return captured, false, ctx.Err()
	}
}

func (m *RateLimitProbing) runRecoveryPhase(ctx context.Context) rateProbeSnapshot {
	snapshot := rateProbeSnapshot{}
	for i := 0; i < rateLimitRecoveryRequests; i++ {
		select {
		case <-ctx.Done():
			return snapshot
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
		if err != nil {
			continue
		}
		resp, err := m.Client.Do(req)
		if err != nil {
			continue
		}

		snapshot.recoveryDone++
		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			snapshot.recoverySuccess++
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			snapshot.recovery429 = true
		}
		if resp.Header.Get("Retry-After") != "" {
			snapshot.recoveryRetryAfter = true
		}
		resp.Body.Close()

		if i+1 < rateLimitRecoveryRequests {
			timer := time.NewTimer(rateLimitRecoveryPause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return snapshot
			case <-timer.C:
			}
		}
	}
	return snapshot
}

func init() {
	RegisterModule("rate_limit_probing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting RateLimitProbing on: %s", target))

		tester := NewRateLimitProbing(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
