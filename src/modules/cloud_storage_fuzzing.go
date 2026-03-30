package modules

import (
	"context"
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
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []CloudStorageFuzzingResult
	client     *http.Client
}

// NewCloudStorageFuzzing creates a new instance.
func NewCloudStorageFuzzing(target string) *CloudStorageFuzzing {
	return &CloudStorageFuzzing{
		Target:     target,
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *CloudStorageFuzzing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

var s3Permutations = []string{
	"", "-dev", "-prod", "-backup", "-static", "-assets", "-media", "-public",
}

func (m *CloudStorageFuzzing) Execute(ctx context.Context) ([]CloudStorageFuzzingResult, error) {
	m.results = make([]CloudStorageFuzzingResult, 0)

	// Extract base name from target (e.g., example.com -> example)
	targetStr := strings.TrimPrefix(m.Target, "http://")
	targetStr = strings.TrimPrefix(targetStr, "https://")
	targetStr = strings.Split(targetStr, "/")[0]
	targetStr = strings.Split(targetStr, ":")[0]

	baseName := strings.Split(targetStr, ".")[0]

	jobs := make(chan string, len(s3Permutations))
	for _, p := range s3Permutations {
		jobs <- baseName + p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucket := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testBucket(ctx, bucket)
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
		return m.results, nil
	case <-ctx.Done():
		<-done
		return m.results, ctx.Err()
	}
}

func (m *CloudStorageFuzzing) testBucket(ctx context.Context, bucketName string) {
	bucketURL := "http://" + bucketName + ".s3.amazonaws.com/"

	req, err := http.NewRequestWithContext(ctx, "GET", bucketURL, nil)
	if err != nil {
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
		// Even forbidden means it exists. OK means it's publicly readable.
		m.mu.Lock()
		m.results = append(m.results, CloudStorageFuzzingResult{
			Target: m.Target,
			Status: "found",
			Detail: "Cloud bucket found: " + bucketURL + " (HTTP " + string(rune(resp.StatusCode)) + ")",
		})
		m.mu.Unlock()
	}
}
