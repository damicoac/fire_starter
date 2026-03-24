package decisiontree

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/log"
)

func newTestLogger() *log.Logger {
	logger := log.NewWithOptions(io.Discard, log.Options{})
	return logger
}

func TestNewTreeValidation(t *testing.T) {
	validTool := ToolDefinition{
		Name: "alpha",
		Condition: func(input ThirdPartyInput) bool {
			return true
		},
		Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
			return ToolResult{ToolName: "alpha"}, nil
		},
	}

	tests := []struct {
		name    string
		logger  *log.Logger
		tools   []ToolDefinition
		wantErr bool
	}{
		{
			name:    "missing logger",
			logger:  nil,
			tools:   []ToolDefinition{validTool},
			wantErr: true,
		},
		{
			name:    "missing tools",
			logger:  newTestLogger(),
			tools:   nil,
			wantErr: true,
		},
		{
			name:   "tool missing name",
			logger: newTestLogger(),
			tools: []ToolDefinition{
				{
					Name: "",
					Condition: func(input ThirdPartyInput) bool {
						return true
					},
					Run: validTool.Run,
				},
			},
			wantErr: true,
		},
		{
			name:   "tool missing condition",
			logger: newTestLogger(),
			tools: []ToolDefinition{
				{
					Name:      "alpha",
					Condition: nil,
					Run:       validTool.Run,
				},
			},
			wantErr: true,
		},
		{
			name:   "tool missing run function",
			logger: newTestLogger(),
			tools: []ToolDefinition{
				{
					Name: "alpha",
					Condition: func(input ThirdPartyInput) bool {
						return true
					},
					Run: nil,
				},
			},
			wantErr: true,
		},
		{
			name:    "valid tree",
			logger:  newTestLogger(),
			tools:   []ToolDefinition{validTool},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTree(tt.logger, tt.tools)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error but got %v", err)
			}
		})
	}
}

func TestSelectTool(t *testing.T) {
	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "fetch-profile",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "profile"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "fetch-profile"}, nil
			},
		},
		{
			Name: "score-risk",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "risk"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "score-risk"}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	selected, err := tree.SelectTool(ThirdPartyInput{Stage: "risk"})
	if err != nil {
		t.Fatalf("unexpected select error: %v", err)
	}
	if selected.Name != "score-risk" {
		t.Fatalf("expected score-risk, got %s", selected.Name)
	}

	_, err = tree.SelectTool(ThirdPartyInput{Stage: "unknown"})
	if !errors.Is(err, ErrNoMatchingTool) {
		t.Fatalf("expected ErrNoMatchingTool, got %v", err)
	}
}

func TestRun_ExecutesLoopUntilResolverStops(t *testing.T) {
	called := make([]string, 0, 2)

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "ingest",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "input"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				called = append(called, "ingest")
				return ToolResult{ToolName: "ingest", Output: map[string]any{"next": "enrich"}}, nil
			},
		},
		{
			Name: "enrich",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "enrich"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				called = append(called, "enrich")
				return ToolResult{ToolName: "enrich", Output: map[string]any{"done": true}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{Stage: "input"}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		switch result.ToolName {
		case "ingest":
			return ThirdPartyInput{Stage: "enrich"}, true, nil
		case "enrich":
			return ThirdPartyInput{}, false, nil
		default:
			return ThirdPartyInput{}, false, errors.New("unexpected tool")
		}
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if len(called) != 2 || called[0] != "ingest" || called[1] != "enrich" {
		t.Fatalf("unexpected call sequence: %v", called)
	}
}

func TestRun_ReturnsErrorOnToolFailure(t *testing.T) {
	expectedErr := errors.New("tool failed")
	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "failing-tool",
			Condition: func(input ThirdPartyInput) bool {
				return true
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{}, expectedErr
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{Stage: "any"}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		return ThirdPartyInput{}, false, nil
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}

func TestRun_ReturnsErrorOnResolverFailure(t *testing.T) {
	expectedErr := errors.New("resolver failed")
	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "ok-tool",
			Condition: func(input ThirdPartyInput) bool {
				return true
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "ok-tool"}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{Stage: "any"}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		return ThirdPartyInput{}, false, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}

func TestRegisterTool_ValidationAndCopy(t *testing.T) {
	withTemporaryRegistry(t, func() {
		err := RegisterTool(ToolDefinition{})
		if err == nil {
			t.Fatalf("expected validation error")
		}

		err = RegisterTool(ToolDefinition{
			Name: "tool-a",
			Condition: func(input ThirdPartyInput) bool {
				return true
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "tool-a"}, nil
			},
		})
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}

		registered := RegisteredTools()
		if len(registered) != 1 {
			t.Fatalf("expected 1 registered tool, got %d", len(registered))
		}

		registered[0].Name = "changed"
		again := RegisteredTools()
		if again[0].Name != "tool-a" {
			t.Fatalf("expected defensive copy from registry, got %q", again[0].Name)
		}
	})
}

func TestNewTreeFromRegistry(t *testing.T) {
	withTemporaryRegistry(t, func() {
		err := RegisterTool(ToolDefinition{
			Name: "ingest",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "input"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "ingest"}, nil
			},
		})
		if err != nil {
			t.Fatalf("unexpected register error: %v", err)
		}

		tree, err := NewTreeFromRegistry(newTestLogger())
		if err != nil {
			t.Fatalf("unexpected tree creation error: %v", err)
		}

		selected, err := tree.SelectTool(ThirdPartyInput{Stage: "input"})
		if err != nil {
			t.Fatalf("unexpected select error: %v", err)
		}
		if selected.Name != "ingest" {
			t.Fatalf("expected ingest tool, got %q", selected.Name)
		}
	})
}

func TestRegisterNode(t *testing.T) {
	withTemporaryRegistry(t, func() {
		err := RegisterNode(
			"enrich",
			func(input ThirdPartyInput) bool {
				return input.Stage == "enrich"
			},
			func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "enrich"}, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected register node error: %v", err)
		}

		tree, err := NewTreeFromRegistry(newTestLogger())
		if err != nil {
			t.Fatalf("unexpected tree creation error: %v", err)
		}

		selected, err := tree.SelectTool(ThirdPartyInput{Stage: "enrich"})
		if err != nil {
			t.Fatalf("unexpected select error: %v", err)
		}
		if selected.Name != "enrich" {
			t.Fatalf("expected enrich tool, got %q", selected.Name)
		}
	})
}

func TestAPITestingFlow_WithDetectedAPI(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalInput := ThirdPartyInput{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageTargetReceived,
		Payload: map[string]any{
			"ip":      "10.10.10.10",
			"has_api": true,
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if !continueFlow {
			finalInput = next
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if !getBool(finalInput.Payload, "api_testing_complete") {
		t.Fatalf("expected api testing to complete, payload: %#v", finalInput.Payload)
	}
}

func TestAPITestingFlow_WithoutDetectedAPI(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalPayload := map[string]any{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageTargetReceived,
		Payload: map[string]any{
			"ip":      "192.168.1.20",
			"has_api": false,
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if result.ToolName == stageAPITestingComplete {
			finalPayload = next.Payload
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if getBool(finalPayload, "recon_complete") {
		t.Fatalf("did not expect recon stage when api is not detected, payload: %#v", finalPayload)
	}
	if !getBool(finalPayload, "api_testing_complete") {
		t.Fatalf("expected completion payload flag, payload: %#v", finalPayload)
	}
}

func TestAPITestingFlow_InvalidIP(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageTargetReceived,
		Payload: map[string]any{
			"ip": "not-an-ip",
		},
	}, DefaultNextInputResolver)
	if err == nil {
		t.Fatalf("expected invalid ip error")
	}
	if !strings.Contains(err.Error(), "invalid ip address") {
		t.Fatalf("expected invalid ip address error, got %v", err)
	}
}

func TestApplicationMappingFlow_FullPath(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalInput := ThirdPartyInput{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageApplicationMappingExplore,
		Payload: map[string]any{
			"target": "https://app.example.local",
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if !continueFlow {
			finalInput = next
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if !getBool(finalInput.Payload, "manual_exploration_complete") {
		t.Fatalf("expected manual exploration to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "entry_points_identified") {
		t.Fatalf("expected entry-point identification to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "metadata_review_complete") {
		t.Fatalf("expected metadata review to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "attack_surface_mapped") {
		t.Fatalf("expected attack surface mapping to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "application_mapping_complete") {
		t.Fatalf("expected application mapping to complete, payload: %#v", finalInput.Payload)
	}
}

func TestApplicationMappingFlow_BranchPrioritizationExpansion(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalPayload := map[string]any{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageApplicationMappingExplore,
		Payload: map[string]any{
			"target":               "https://app.example.local",
			"expand_prioritization": true,
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if result.ToolName == stageApplicationMappingComplete {
			finalPayload = next.Payload
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if !getBool(finalPayload, "sensitive_functions_prioritized") {
		t.Fatalf("expected sensitive function prioritization, payload: %#v", finalPayload)
	}
	if !getBool(finalPayload, "expanded_prioritization_complete") {
		t.Fatalf("expected expanded prioritization branch to run, payload: %#v", finalPayload)
	}
}

func TestApplicationMappingFlow_InvalidPayload(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageApplicationMappingExplore,
		Payload: map[string]any{},
	}, DefaultNextInputResolver)
	if err == nil {
		t.Fatalf("expected missing target payload error")
	}
	if !strings.Contains(err.Error(), "missing payload key \"target\"") {
		t.Fatalf("expected missing target payload error, got %v", err)
	}
}

func TestActiveTestingFlow_FullPath(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalInput := ThirdPartyInput{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageActiveTestingAccessControl,
		Payload: map[string]any{
			"target": "https://app.example.local",
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if !continueFlow {
			finalInput = next
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if !getBool(finalInput.Payload, "idor_tested") {
		t.Fatalf("expected access control checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "business_logic_tested") {
		t.Fatalf("expected business logic checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "xss_tested") {
		t.Fatalf("expected xss checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "injection_tested") {
		t.Fatalf("expected injection checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "error_handling_tested") {
		t.Fatalf("expected error handling checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "http_methods_checked") {
		t.Fatalf("expected configuration checks to complete, payload: %#v", finalInput.Payload)
	}
	if !getBool(finalInput.Payload, "active_testing_complete") {
		t.Fatalf("expected active testing completion flag, payload: %#v", finalInput.Payload)
	}
}

func TestActiveTestingFlow_BranchSkipXSS(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	finalPayload := map[string]any{}
	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageActiveTestingAccessControl,
		Payload: map[string]any{
			"target":   "https://app.example.local",
			"test_xss": false,
		},
	}, func(ctx context.Context, result ToolResult) (ThirdPartyInput, bool, error) {
		next, continueFlow, resolverErr := DefaultNextInputResolver(ctx, result)
		if result.ToolName == stageActiveTestingComplete {
			finalPayload = next.Payload
		}
		return next, continueFlow, resolverErr
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if getBool(finalPayload, "xss_tested") {
		t.Fatalf("did not expect xss stage when disabled, payload: %#v", finalPayload)
	}
	if !getBool(finalPayload, "xss_skipped") {
		t.Fatalf("expected xss skip marker, payload: %#v", finalPayload)
	}
	if !getBool(finalPayload, "injection_tested") {
		t.Fatalf("expected injection stage after skipping xss, payload: %#v", finalPayload)
	}
}

func TestActiveTestingFlow_InvalidPayload(t *testing.T) {
	tree, err := NewTreeFromRegistry(newTestLogger())
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.Run(context.Background(), ThirdPartyInput{
		Stage: stageActiveTestingAccessControl,
		Payload: map[string]any{},
	}, DefaultNextInputResolver)
	if err == nil {
		t.Fatalf("expected missing target payload error")
	}
	if !strings.Contains(err.Error(), "missing payload key \"target\"") {
		t.Fatalf("expected missing target payload error, got %v", err)
	}
}

func withTemporaryRegistry(t *testing.T, run func()) {
	t.Helper()

	original := snapshotRegisteredTools()
	replaceRegisteredTools(nil)

	defer func() {
		replaceRegisteredTools(original)
	}()

	run()
}
