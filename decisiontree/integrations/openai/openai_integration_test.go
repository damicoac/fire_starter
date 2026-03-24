// File overview:
// Test coverage for this module. These tests exist to lock expected behavior and prevent regressions in stage routing, payload handling, and integration boundaries.

package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blackwater/decisiontree/core"
	"github.com/charmbracelet/log"
)

type fakeStageGuidanceGenerator struct {
	guidance string
	err      error
}

func newTestLogger() *log.Logger {
	logger := log.NewWithOptions(io.Discard, log.Options{})
	return logger
}

func (f fakeStageGuidanceGenerator) GenerateStageGuidance(ctx context.Context, instructions string, userPrompt string) (string, error) {
	_ = ctx
	_ = instructions
	_ = userPrompt
	if f.err != nil {
		return "", f.err
	}
	return f.guidance, nil
}

func TestExtractOutputText(t *testing.T) {
	outputTextResponse := openAIResponsesResponse{OutputText: "direct text"}
	logMockData(t, "extract-output direct response", outputTextResponse)
	fromOutputText := extractOutputText(outputTextResponse)
	if fromOutputText != "direct text" {
		t.Fatalf("expected direct text, got %q", fromOutputText)
	}

	outputItemsResponse := openAIResponsesResponse{
		Output: []openAIOutputResponseItem{
			{
				Type: "message",
				Content: []openAIOutputContentBlock{
					{Type: "output_text", Text: "line one"},
					{Type: "output_text", Text: "line two"},
				},
			},
		},
	}
	logMockData(t, "extract-output output items response", outputItemsResponse)
	fromOutputItems := extractOutputText(outputItemsResponse)
	if fromOutputItems != "line one\nline two" {
		t.Fatalf("expected joined content text, got %q", fromOutputItems)
	}
}

func TestOpenAIResponsesClient_GenerateStageGuidance_Success(t *testing.T) {
	receivedAuth := ""
	receivedContentType := ""
	receivedBody := openAIResponsesRequest{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		if err := json.Unmarshal(body, &receivedBody); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"stage guidance text"}]}]}`))
	}))
	defer server.Close()

	logMockData(t, "openai-http-success mocked api response", map[string]any{"output": []map[string]any{{"type": "message", "role": "assistant", "content": []map[string]any{{"type": "output_text", "text": "stage guidance text"}}}}})

	client, err := NewOpenAIResponsesClient("test-key", "gpt-5.4")
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	client.endpoint = server.URL
	client.httpClient = server.Client()

	guidance, err := client.GenerateStageGuidance(context.Background(), "sys instructions", "user prompt")
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}
	if guidance != "stage guidance text" {
		t.Fatalf("expected guidance text, got %q", guidance)
	}
	if receivedAuth != "Bearer test-key" {
		t.Fatalf("expected auth header, got %q", receivedAuth)
	}
	if receivedContentType != "application/json" {
		t.Fatalf("expected content-type header, got %q", receivedContentType)
	}
	if receivedBody.Model != "gpt-5.4" {
		t.Fatalf("expected model gpt-5.4, got %q", receivedBody.Model)
	}
	if receivedBody.Instructions != "sys instructions" {
		t.Fatalf("expected instructions in payload, got %q", receivedBody.Instructions)
	}
	if len(receivedBody.Input) != 1 || receivedBody.Input[0].Role != "user" || receivedBody.Input[0].Content != "user prompt" {
		t.Fatalf("unexpected input payload: %#v", receivedBody.Input)
	}
}

func TestOpenAIResponsesClient_GenerateStageGuidance_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request"}`))
	}))
	defer server.Close()

	logMockData(t, "openai-http-error mocked api response", map[string]any{"error": "invalid request"})

	client, err := NewOpenAIResponsesClient("test-key", "gpt-5")
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	client.endpoint = server.URL
	client.httpClient = server.Client()

	_, err = client.GenerateStageGuidance(context.Background(), "sys", "user")
	if err == nil {
		t.Fatalf("expected api error")
	}
	if !strings.Contains(err.Error(), "openai api returned status 400") {
		t.Fatalf("expected status error message, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid request") {
		t.Fatalf("expected api body in error message, got %v", err)
	}
}

func TestOpenAIStageObserver_OnStageCompleted(t *testing.T) {
	mockedGuidance := "analyst steps"
	logMockData(t, "stage-observer mocked guidance", mockedGuidance)
	observer, err := NewOpenAIStageObserver(fakeStageGuidanceGenerator{guidance: mockedGuidance})
	if err != nil {
		t.Fatalf("unexpected observer constructor error: %v", err)
	}

	result := core.ToolResult{
		ToolName: "api-testing.recon",
		Output: map[string]any{
			"continue": true,
		},
	}
	input := core.ThirdPartyInput{
		Stage: "api-testing.recon",
		Payload: map[string]any{
			"ip": "10.10.10.10",
		},
	}

	err = observer.OnStageCompleted(context.Background(), input, &result)
	if err != nil {
		t.Fatalf("unexpected observer error: %v", err)
	}

	agentGuidanceAny, ok := result.Output["agent_guidance"]
	if !ok {
		t.Fatalf("expected agent_guidance key in output")
	}
	agentGuidance, ok := agentGuidanceAny.(map[string]any)
	if !ok {
		t.Fatalf("expected agent_guidance map, got %T", agentGuidanceAny)
	}
	if agentGuidance["stage"] != "api-testing.recon" {
		t.Fatalf("expected stage in guidance, got %#v", agentGuidance)
	}
	if agentGuidance["guidance"] != "analyst steps" {
		t.Fatalf("expected generated guidance text, got %#v", agentGuidance)
	}
}

func TestRunWithObserver_ReturnsObserverError(t *testing.T) {
	expectedErr := errors.New("observer failed")
	observer := fakeTreeObserver{err: expectedErr}

	tree, err := core.NewTree(newTestLogger(), []core.ToolDefinition{
		{
			Name: "only-stage",
			Condition: func(input core.ThirdPartyInput) bool {
				return input.Stage == "stage.one"
			},
			Run: func(ctx context.Context, input core.ThirdPartyInput) (core.ToolResult, error) {
				return core.ToolResult{ToolName: "only-stage", Output: map[string]any{"continue": false}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithObserver(context.Background(), core.ThirdPartyInput{Stage: "stage.one"}, core.DefaultNextInputResolver, observer)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected observer error, got %v", err)
	}
	if !strings.Contains(err.Error(), "observer failed") {
		t.Fatalf("expected observer failure context, got %v", err)
	}
}

type fakeTreeObserver struct {
	err error
}

func (f fakeTreeObserver) OnStageCompleted(ctx context.Context, input core.ThirdPartyInput, result *core.ToolResult) error {
	_ = ctx
	_ = input
	_ = result
	return f.err
}

type openAICallLimitTransport struct {
	base             http.RoundTripper
	maxCalls         int32
	calls            int32
	capturedRequests []openAIResponsesRequest
}

func (t *openAICallLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	callCount := atomic.AddInt32(&t.calls, 1)
	if callCount > t.maxCalls {
		return nil, errors.New("openai endpoint call limit exceeded")
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))

		captured := openAIResponsesRequest{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &captured); err != nil {
				return nil, err
			}
		}
		t.capturedRequests = append(t.capturedRequests, captured)
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func TestOpenAIResponsesClient_GenerateStageGuidance_RealAPI(t *testing.T) {
	if os.Getenv("OPENAI_INTEGRATION_TEST") != "1" {
		t.Skip("set OPENAI_INTEGRATION_TEST=1 to run real OpenAI integration test")
	}

	client, err := NewOpenAIResponsesClientFromEnv("gpt-4.1-mini")
	if err != nil {
		t.Fatalf("create openai client from environment: %v", err)
	}

	transport := &openAICallLimitTransport{base: http.DefaultTransport, maxCalls: 4}
	client.httpClient = &http.Client{Timeout: 45 * time.Second, Transport: transport}

	mockedInstructions := "Respond with exactly: integration test ok"
	mockedUserPrompt := "Return the exact phrase now."
	logMockData(t, "openai-realapi mocked request", map[string]any{"instructions": mockedInstructions, "input": mockedUserPrompt})

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	guidance, err := client.GenerateStageGuidance(ctx, mockedInstructions, mockedUserPrompt)
	if err != nil {
		t.Fatalf("generate guidance from real OpenAI API: %v", err)
	}

	if strings.TrimSpace(guidance) == "" {
		t.Fatalf("expected non-empty response guidance")
	}
	if !strings.Contains(strings.ToLower(guidance), "integration test ok") {
		t.Fatalf("expected integration test phrase in response, got %q", guidance)
	}

	callCount := atomic.LoadInt32(&transport.calls)
	if callCount > 4 {
		t.Fatalf("expected at most 4 openai endpoint calls, got %d", callCount)
	}
	if len(transport.capturedRequests) == 0 {
		t.Fatalf("expected captured request payload")
	}

	captured := transport.capturedRequests[0]
	logMockData(t, "openai-realapi captured request payload", captured)
	if captured.Model != "gpt-4.1-mini" {
		t.Fatalf("expected model gpt-4.1-mini in captured payload, got %q", captured.Model)
	}
	if captured.Instructions != mockedInstructions {
		t.Fatalf("expected mocked instructions in captured payload, got %q", captured.Instructions)
	}
	if len(captured.Input) != 1 || captured.Input[0].Role != "user" || captured.Input[0].Content != mockedUserPrompt {
		t.Fatalf("expected mocked input in captured payload, got %#v", captured.Input)
	}
}
