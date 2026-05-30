package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ReplaciveFuzzingResult holds the result of the ReplaciveFuzzing module execution.
type ReplaciveFuzzingResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ReplaciveFuzzing executes the replacive_fuzzing security technique.
type ReplaciveFuzzing struct {
	BaseModule
	Target  string
	results []ReplaciveFuzzingResult
}

// NewReplaciveFuzzing creates a new instance.
func NewReplaciveFuzzing(target string) *ReplaciveFuzzing {
	return &ReplaciveFuzzing{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *ReplaciveFuzzing) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

var fuzzingStrings = []string{
	"'", "\"", "''", "\"\"", ";", "--", "/*", "*/",
	"%", "_", "[]", "{}", "()", "\\", "/",
	"\x00", "\x0a", "\x0d", "\n", "\r",
	"1/0", "9999999999999999999999999999999999",
	"-1", "-2147483648", "2147483647",
	"../../../../../../../../../../etc/passwd",
	"<script>alert(1)</script>",
}

func (m *ReplaciveFuzzing) Execute(ctx context.Context) ([]ReplaciveFuzzingResult, error) {
	m.results = make([]ReplaciveFuzzingResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	jobs := make(chan string, len(fuzzingStrings))
	for _, p := range fuzzingStrings {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testPayload(ctx, parsedURL, payload)
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

func (m *ReplaciveFuzzing) testPayload(ctx context.Context, u *url.URL, payload string) {
	query := u.Query()
	testURL := *u

	if len(query) > 0 {
		for key := range query {
			query.Set(key, payload)
		}
		testURL.RawQuery = query.Encode()
	} else {
		testURL.Path = testURL.Path + "/" + payload
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusInternalServerError {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "Fuzzing payload caused HTTP 500 Internal Server Error: "+payload)
		m.results = append(m.results, ReplaciveFuzzingResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "Fuzzing payload caused HTTP 500 Internal Server Error: " + payload,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("replacive_fuzzing", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting ReplaciveFuzzing on: %s", target))

		tester := NewReplaciveFuzzing(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
