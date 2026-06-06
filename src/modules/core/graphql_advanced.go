package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type GraphQLAdvancedResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type GraphQLAdvanced struct {
	BaseModule
	Target  string
	results []GraphQLAdvancedResult
}

func NewGraphQLAdvanced(target string) *GraphQLAdvanced {
	return &GraphQLAdvanced{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 1, // Don't want to actually DoS the target
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *GraphQLAdvanced) Execute(ctx context.Context) ([]GraphQLAdvancedResult, error) {
	m.results = make([]GraphQLAdvancedResult, 0)

	endpoints := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return m.results, ctx.Err()
		default:
			m.testBatching(ctx, ep)
			m.testDeepQuery(ctx, ep)
		}
	}

	return m.results, nil
}

func (m *GraphQLAdvanced) testBatching(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint

	// Test array batching payload
	payload := `[{"query":"query{__typename}"},{"query":"query{__typename}"}]`

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// If it returns an array of results, batching is enabled
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(strings.TrimSpace(bodyStr), "[") {
		m.Mu.Lock()
		m.RecordPoC(req, []byte(payload), fmt.Sprintf("GraphQL Query Batching Enabled at: %s", testURL))
		m.results = append(m.results, GraphQLAdvancedResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("GraphQL endpoint supports query batching (potential DoS/Brute Force): %s", testURL),
		})
		m.Mu.Unlock()
	}
}

func (m *GraphQLAdvanced) testDeepQuery(ctx context.Context, endpoint string) {
	testURL := m.Target + endpoint

	// Test alias batching / deep query using aliases
	payload := `{"query":"query{a1:__typename,a2:__typename,a3:__typename,a4:__typename,a5:__typename}"}`

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "a5") {
		m.Mu.Lock()
		m.RecordPoC(req, []byte(payload), fmt.Sprintf("GraphQL Alias Batching / Deep Query Allowed at: %s", testURL))
		m.results = append(m.results, GraphQLAdvancedResult{
			Target: m.Target,
			Status: "vulnerable",
			Detail: fmt.Sprintf("GraphQL endpoint does not restrict query complexity/aliases: %s", testURL),
		})
		m.Mu.Unlock()
	}
}

func init() {
	RegisterModule("graphql_advanced_attacks", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting GraphQLAdvanced on: %s", target))
		tester := NewGraphQLAdvanced(target)
		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
