package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GraphqlIntrospectionResult holds the result of the GraphqlIntrospection module execution.
type GraphqlIntrospectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// GraphqlIntrospection executes the graphql_introspection security technique.
type GraphqlIntrospection struct {
	Target     string
	maxThreads int
	mu         sync.Mutex
	results    []GraphqlIntrospectionResult
	client     *http.Client
}

// NewGraphqlIntrospection creates a new instance of GraphqlIntrospection.
func NewGraphqlIntrospection(target string) *GraphqlIntrospection {
	return &GraphqlIntrospection{
		Target:     EnsureHTTPPrefix(target),
		maxThreads: 1,
		client:     NewHTTPClient(10 * time.Second),
	}
}

func (m *GraphqlIntrospection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.maxThreads = count
}

func (m *GraphqlIntrospection) Execute(ctx context.Context) ([]GraphqlIntrospectionResult, error) {
	m.results = make([]GraphqlIntrospectionResult, 0)

	endpoints := []string{
		m.Target,
		strings.TrimRight(m.Target, "/") + "/graphql",
		strings.TrimRight(m.Target, "/") + "/api/graphql",
		strings.TrimRight(m.Target, "/") + "/v1/graphql",
	}

	query := map[string]string{
		"query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n      }\n    }\n  ",
	}
	payload, _ := json.Marshal(query)

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return m.results, ctx.Err()
		default:
			req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				bodyStr := string(bodyBytes)
				if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "queryType") {
					m.mu.Lock()
					m.results = append(m.results, GraphqlIntrospectionResult{
						Target: m.Target,
						Status: "vulnerable",
						Detail: "GraphQL Introspection enabled at " + endpoint,
					})
					m.mu.Unlock()
					return m.results, nil // found one, can stop
				}
			}
		}
	}

	return m.results, nil
}
