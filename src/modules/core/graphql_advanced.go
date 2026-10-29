package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
		m.Target,
		strings.TrimRight(m.Target, "/") + "/graphql",
		strings.TrimRight(m.Target, "/") + "/api/graphql",
		strings.TrimRight(m.Target, "/") + "/v1/graphql",
	}

	probes := 0
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return m.results, ctx.Err()
		default:
			probes += m.testBatching(ctx, ep)
			probes += m.testDeepQuery(ctx, ep)
		}
	}

	if probes == 0 {
		m.results = append(m.results, GraphQLAdvancedResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "No GraphQL endpoint responded to advanced technique probes.",
		})
	}

	return m.results, nil
}

// graphqlRawMessageHasContent reports whether a raw JSON field carries a
// non-null value.
func graphqlRawMessageHasContent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// graphqlRawMessageIsEmptyArray reports whether a raw JSON field is an empty
// array ("[]"), which per the GraphQL spec is not an error outcome.
func graphqlRawMessageIsEmptyArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("[]"))
}

func (m *GraphQLAdvanced) testBatching(ctx context.Context, endpoint string) int {
	testURL := endpoint

	// Test array batching payload
	payload := `[{"query":"query{__typename}"},{"query":"query{__typename}"}]`

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	bodyBytes, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		return 0
	}

	// A vulnerable batched response is a JSON array with >= 2 entries, each
	// carrying non-empty data and none carrying errors.
	if resp.StatusCode == http.StatusOK {
		var results []struct {
			Data   json.RawMessage `json:"data"`
			Errors json.RawMessage `json:"errors"`
		}
		if err := json.Unmarshal(bodyBytes, &results); err == nil && len(results) >= 2 {
			allData := true
			anyErrors := false
			for _, entry := range results {
				if !graphqlRawMessageHasContent(entry.Data) {
					allData = false
				}
				if graphqlRawMessageHasContent(entry.Errors) && !graphqlRawMessageIsEmptyArray(entry.Errors) {
					anyErrors = true
				}
			}
			if allData && !anyErrors {
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
	}
	return 1
}

func (m *GraphQLAdvanced) testDeepQuery(ctx context.Context, endpoint string) int {
	testURL := endpoint

	// Test alias batching / deep query using aliases
	payload := `{"query":"query{a1:__typename,a2:__typename,a3:__typename,a4:__typename,a5:__typename}"}`

	req, err := http.NewRequestWithContext(ctx, "POST", testURL, bytes.NewBufferString(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	bodyBytes, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
	if readErr != nil {
		return 0
	}

	// Vulnerable only when the response data object actually carries all
	// five aliases with non-null values — validation errors echoing the
	// alias names must not count.
	if resp.StatusCode == http.StatusOK {
		var parsed struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(bodyBytes, &parsed); err == nil && len(parsed.Data) > 0 {
			allAliases := true
			for _, alias := range []string{"a1", "a2", "a3", "a4", "a5"} {
				if v, ok := parsed.Data[alias]; !ok || v == nil {
					allAliases = false
					break
				}
			}
			if allAliases {
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
	}
	return 1
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
