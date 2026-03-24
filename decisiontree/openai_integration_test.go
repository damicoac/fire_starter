package decisiontree

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeStageGuidanceGenerator struct {
	guidance string
	err      error
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
	fromOutputText := extractOutputText(openAIResponsesResponse{OutputText: "direct text"})
	if fromOutputText != "direct text" {
		t.Fatalf("expected direct text, got %q", fromOutputText)
	}

	fromOutputItems := extractOutputText(openAIResponsesResponse{
		Output: []openAIOutputResponseItem{
			{
				Type: "message",
				Content: []openAIOutputContentBlock{
					{Type: "output_text", Text: "line one"},
					{Type: "output_text", Text: "line two"},
				},
			},
		},
	})
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
}

func TestOpenAIStageObserver_OnStageCompleted(t *testing.T) {
	observer, err := NewOpenAIStageObserver(fakeStageGuidanceGenerator{guidance: "analyst steps"})
	if err != nil {
		t.Fatalf("unexpected observer constructor error: %v", err)
	}

	result := ToolResult{
		ToolName: "api-testing.recon",
		Output: map[string]any{
			"continue": true,
		},
	}
	input := ThirdPartyInput{
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

	tree, err := NewTree(newTestLogger(), []ToolDefinition{
		{
			Name: "only-stage",
			Condition: func(input ThirdPartyInput) bool {
				return input.Stage == "stage.one"
			},
			Run: func(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
				return ToolResult{ToolName: "only-stage", Output: map[string]any{"continue": false}}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected tree creation error: %v", err)
	}

	err = tree.RunWithObserver(context.Background(), ThirdPartyInput{Stage: "stage.one"}, DefaultNextInputResolver, observer)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected observer error, got %v", err)
	}
}

type fakeTreeObserver struct {
	err error
}

func (f fakeTreeObserver) OnStageCompleted(ctx context.Context, input ThirdPartyInput, result *ToolResult) error {
	_ = ctx
	_ = input
	_ = result
	return f.err
}
