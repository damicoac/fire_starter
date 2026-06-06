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

// HttpParameterPollutionHppResult holds the result of the HttpParameterPollutionHpp module execution.
type HttpParameterPollutionHppResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HttpParameterPollutionHpp executes the http_parameter_pollution_hpp security technique.
type HttpParameterPollutionHpp struct {
	BaseModule
	Target  string
	results []HttpParameterPollutionHppResult
}

// NewHttpParameterPollutionHpp creates a new instance.
func NewHttpParameterPollutionHpp(target string) *HttpParameterPollutionHpp {
	return &HttpParameterPollutionHpp{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *HttpParameterPollutionHpp) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
}

func (m *HttpParameterPollutionHpp) Execute(ctx context.Context) ([]HttpParameterPollutionHppResult, error) {
	m.results = make([]HttpParameterPollutionHppResult, 0)

	parsedURL, err := url.Parse(m.Target)
	if err != nil {
		return m.results, err
	}

	// For HPP, we need to find parameters. If none exist, we guess some.
	query := parsedURL.Query()
	if len(query) == 0 {
		query.Add("user", "1")
		query.Add("id", "1")
	}

	jobs := make(chan string, len(query))
	for key := range query {
		jobs <- key
	}
	close(jobs)

	var wg sync.WaitGroup

	for i := 0; i < m.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for param := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					m.testParameter(ctx, parsedURL, query, param)
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

func (m *HttpParameterPollutionHpp) testParameter(ctx context.Context, u *url.URL, originalQuery url.Values, paramToPollute string) {
	testURL := *u
	q := url.Values{}

	// Copy original
	for k, v := range originalQuery {
		q[k] = v
	}

	// Pollute the target parameter
	q.Add(paramToPollute, "polluted_value_12345")
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(bodyBytes)
	originalVal := originalQuery.Get(paramToPollute)

	// If the server throws a 500 (array instead of string) or concatenates the values (ASP.NET style)
	if resp.StatusCode == http.StatusInternalServerError || (originalVal != "" && strings.Contains(bodyStr, originalVal+",polluted_value_12345")) {
		m.Mu.Lock()
		m.RecordPoC(req, nil, "HTTP Parameter Pollution detected on parameter: "+paramToPollute)
		m.results = append(m.results, HttpParameterPollutionHppResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: "HTTP Parameter Pollution detected on parameter: " + paramToPollute,
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("http_parameter_pollution_hpp", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting HttpParameterPollutionHpp on: %s", target))

		tester := NewHttpParameterPollutionHpp(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
