package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudStorageFuzzingResult holds the result of the CloudStorageFuzzing module execution.
type CloudStorageFuzzingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CloudStorageFuzzing executes the cloud_storage_fuzzing security technique.
type CloudStorageFuzzing struct {
	BaseModule
	Target        string
	results       []CloudStorageFuzzingResult
	probeFailures int
	lastProbeErr  error
}

// NewCloudStorageFuzzing creates a new instance.
func NewCloudStorageFuzzing(target string) *CloudStorageFuzzing {
	return &CloudStorageFuzzing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: target,
	}
}

func (m *CloudStorageFuzzing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var storagePermutations = []string{
	"", "-dev", "-prod", "-backup", "-static", "-assets", "-media", "-public",
}

// storageProbe identifies one provider endpoint derived from a candidate name.
type storageProbe struct {
	provider string
	url      string
}

// storageProbesFor builds the S3, GCS, and Azure endpoints for a candidate name.
func storageProbesFor(name string) []storageProbe {
	return []storageProbe{
		{provider: "s3", url: "https://" + name + ".s3.amazonaws.com/"},
		{provider: "gcs", url: "https://storage.googleapis.com/" + name + "/"},
		{provider: "azure", url: "https://" + name + ".blob.core.windows.net/" + name},
	}
}

func (m *CloudStorageFuzzing) Execute(ctx context.Context) ([]CloudStorageFuzzingResult, error) {
	m.results = make([]CloudStorageFuzzingResult, 0)
	m.probeFailures = 0
	m.lastProbeErr = nil

	// Extract base name from target (e.g., example.com -> example)
	targetStr := strings.TrimPrefix(m.Target, "http://")
	targetStr = strings.TrimPrefix(targetStr, "https://")
	targetStr = strings.Split(targetStr, "/")[0]
	targetStr = strings.Split(targetStr, ":")[0]

	baseName := strings.Split(targetStr, ".")[0]

	probes := make([]storageProbe, 0, len(storagePermutations)*3)
	for _, p := range storagePermutations {
		probes = append(probes, storageProbesFor(baseName+p)...)
	}

	jobs := make(chan storageProbe, len(probes))
	for _, probe := range probes {
		jobs <- probe
	}
	close(jobs)

	var wg sync.WaitGroup

	for range m.MaxThreads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for probe := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testProbe(ctx, probe)
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
		if len(m.results) == 0 && ctx.Err() == nil {
			detail := "No publicly readable cloud storage buckets identified and no bucket states could be classified on tested S3, GCS, and Azure endpoints."
			if m.probeFailures > 0 && m.lastProbeErr != nil {
				detail = fmt.Sprintf("Cloud storage probes failed: %v", m.lastProbeErr)
			}
			m.results = append(m.results, CloudStorageFuzzingResult{
				Target: m.Target,
				Status: statusFromEvidence(EvidenceWeak, false),
				Detail: detail,
			})
		}
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

// recordProbeFailure tracks a probe that could not complete so an
// all-probes-failed run can be reported instead of silently appearing clean.
func (m *CloudStorageFuzzing) recordProbeFailure(probe storageProbe, err error) {
	m.Mu.Lock()
	m.probeFailures++
	m.lastProbeErr = err
	m.Mu.Unlock()
}

func (m *CloudStorageFuzzing) testProbe(ctx context.Context, probe storageProbe) {
	req, err := http.NewRequestWithContext(ctx, "GET", probe.url, nil)
	if err != nil {
		m.recordProbeFailure(probe, err)
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		m.recordProbeFailure(probe, err)
		return
	}
	defer resp.Body.Close()

	body, _, err := ReadBoundedBodyWithTruncation(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		m.recordProbeFailure(probe, err)
		return
	}
	bodyStr := string(body)

	var status, detail string
	switch {
	case probe.provider == "s3" && resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "<ListBucketResult"):
		status = statusFromEvidence(EvidenceConfirmed, false)
		detail = fmt.Sprintf("Publicly readable S3 bucket found: %s (HTTP 200 with ListBucketResult)", probe.url)
	case probe.provider == "s3" && resp.StatusCode == http.StatusOK:
		// A 200 without the ListBucketResult document (e.g. a proxy or WAF
		// answering for everything) is not proof of public readability.
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("S3 endpoint %s responded HTTP 200 without a ListBucketResult document; public-read status unverified.", probe.url)
	case probe.provider == "s3" && resp.StatusCode == http.StatusForbidden:
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("Private S3 bucket exists: %s (HTTP 403 Forbidden)", probe.url)
	case probe.provider == "gcs" && resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "<ListBucketResult"):
		status = statusFromEvidence(EvidenceConfirmed, false)
		detail = fmt.Sprintf("Publicly listable GCS bucket found: %s (HTTP 200 with ListBucketResult)", probe.url)
	case probe.provider == "gcs" && resp.StatusCode == http.StatusOK:
		// A 200 without the list document is not proof of public listability
		// (e.g. a proxy or WAF answering for everything).
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("GCS endpoint %s responded HTTP 200 without a ListBucketResult document; public-listability unverified.", probe.url)
	case probe.provider == "gcs" && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound):
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("GCS bucket %s appears to exist but is not publicly listable (HTTP %d).", probe.url, resp.StatusCode)
	case probe.provider == "azure" && resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "<EnumerationResults"):
		status = statusFromEvidence(EvidenceConfirmed, false)
		detail = fmt.Sprintf("Publicly readable Azure blob container found: %s (HTTP 200 with blob listing)", probe.url)
	case probe.provider == "azure" && resp.StatusCode == http.StatusOK:
		// A 200 without the blob-listing document is not proof of public
		// readability (e.g. a proxy or WAF answering for everything).
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("Azure endpoint %s responded HTTP 200 without a blob-listing document; public-read status unverified.", probe.url)
	case probe.provider == "azure" && resp.StatusCode == http.StatusForbidden:
		status = statusFromEvidence(EvidenceWeak, false)
		detail = fmt.Sprintf("Azure blob container %s appears to exist but is not publicly readable (HTTP 403 Forbidden).", probe.url)
	case probe.provider == "azure" && resp.StatusCode == http.StatusNotFound && strings.Contains(bodyStr, "ContainerNotFound"):
		// Container does not exist — not a finding.
		return
	default:
		// Unrecognized status; not a finding.
		return
	}

	m.Mu.Lock()
	if status == statusFromEvidence(EvidenceConfirmed, false) {
		m.RecordPoC(req, nil, detail)
	}
	m.results = append(m.results, CloudStorageFuzzingResult{
		Target: m.Target,
		Status: status,
		Detail: detail,
	})
	m.Mu.Unlock()
}

func init() {
	RegisterModule("cloud_storage_fuzzing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		onLog(fmt.Sprintf("Starting CloudStorageFuzzing on: %s", target))

		tester := NewCloudStorageFuzzing(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
