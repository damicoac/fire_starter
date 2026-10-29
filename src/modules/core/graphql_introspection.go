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

// GraphqlIntrospectionResult holds the result of the GraphqlIntrospection module execution.
type GraphqlIntrospectionResult struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// GraphqlIntrospection executes the graphql_introspection security technique.
type GraphqlIntrospection struct {
	BaseModule
	Target  string
	results []GraphqlIntrospectionResult
}

// NewGraphqlIntrospection creates a new instance of GraphqlIntrospection.
func NewGraphqlIntrospection(target string) *GraphqlIntrospection {
	return &GraphqlIntrospection{
		BaseModule: BaseModule{
			Client:     NewHTTPClient(10 * time.Second),
			MaxThreads: 5,
		},
		Target: EnsureHTTPPrefix(target),
	}
}

func (m *GraphqlIntrospection) SetThreads(count int) {
	if count < 1 {
		count = 1
	}
	m.MaxThreads = count
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
		"query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types { name }\n      }\n    }\n  ",
	}
	payload, _ := json.Marshal(query)

	probed := false

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

			resp, err := m.Client.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, readErr := ReadBoundedBody(resp.Body, MaxResponseBodyBytes)
			resp.Body.Close()
			if readErr != nil {
				continue
			}
			probed = true

			if resp.StatusCode == http.StatusOK {
				var parsed struct {
					Data struct {
						Schema struct {
							Types []json.RawMessage `json:"types"`
						} `json:"__schema"`
					} `json:"data"`
				}
				// Require real introspection data: a hardened server echoing the
				// blocked field name in its error body must not count.
				if err := json.Unmarshal(bodyBytes, &parsed); err == nil && len(parsed.Data.Schema.Types) > 0 {
					m.Mu.Lock()
					m.RecordPoC(req, nil, "GraphQL Introspection enabled at "+endpoint)
					m.results = append(m.results, GraphqlIntrospectionResult{
						Target: m.Target,
						Status: "vulnerable",
						Detail: "GraphQL Introspection enabled at " + endpoint,
					})
					m.Mu.Unlock()
					return m.results, nil // found one, can stop
				}
			}
		}
	}

	if !probed {
		m.results = append(m.results, GraphqlIntrospectionResult{
			Target: m.Target,
			Status: "inconclusive",
			Detail: "No GraphQL endpoint produced a readable response; introspection status unknown.",
		})
	}

	return m.results, nil
}

func init() {
	RegisterModule("graphql_introspection", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {

		target := PayloadString(payload, "url", "http://127.0.0.1")
		onLog(fmt.Sprintf("Starting GraphqlIntrospection on: %s", target))

		tester := NewGraphqlIntrospection(target)

		return ModuleWrapper{
			Module: tester,
			ExecuteFunc: func(ctx context.Context) (any, error) {
				return tester.Execute(ctx)
			},
		}, nil
	})
}
