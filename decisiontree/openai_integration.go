package decisiontree

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultOpenAIResponsesEndpoint = "https://api.openai.com/v1/responses"

// StageGuidanceGenerator abstracts model-backed guidance generation for testability.
type StageGuidanceGenerator interface {
	GenerateStageGuidance(ctx context.Context, instructions string, userPrompt string) (string, error)
}

// OpenAIResponsesClient calls the OpenAI Responses API using raw HTTP.
type OpenAIResponsesClient struct {
	apiKey     string
	model      string
	endpoint   string
	httpClient *http.Client
}

// NewOpenAIResponsesClient validates required inputs and constructs a reusable client.
func NewOpenAIResponsesClient(apiKey string, model string) (*OpenAIResponsesClient, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("openai api key is required")
	}
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("openai model is required")
	}

	return &OpenAIResponsesClient{
		apiKey:   apiKey,
		model:    model,
		endpoint: defaultOpenAIResponsesEndpoint,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}, nil
}

// NewOpenAIResponsesClientFromEnv loads OPENAI_API_KEY and builds a configured client.
func NewOpenAIResponsesClientFromEnv(model string) (*OpenAIResponsesClient, error) {
	apiKey, ok := os.LookupEnv("OPENAI_API_KEY")
	if !ok {
		return nil, errors.New("OPENAI_API_KEY is not set")
	}
	return NewOpenAIResponsesClient(apiKey, model)
}

// GenerateStageGuidance submits stage prompts and returns assistant guidance text.
func (c *OpenAIResponsesClient) GenerateStageGuidance(ctx context.Context, instructions string, userPrompt string) (string, error) {
	requestBody := openAIResponsesRequest{
		Model:        c.model,
		Instructions: instructions,
		Input: []openAIInputMessage{
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("marshal openai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create openai request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute openai request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read openai response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("openai api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	var parsed openAIResponsesResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return "", fmt.Errorf("decode openai response: %w", err)
	}

	guidance := extractOutputText(parsed)
	if strings.TrimSpace(guidance) == "" {
		return "", errors.New("openai response did not contain output_text")
	}

	return guidance, nil
}

// OpenAIStageObserver injects model guidance into each stage output.
type OpenAIStageObserver struct {
	generator StageGuidanceGenerator
}

// NewOpenAIStageObserver validates dependencies for runtime stage observation.
func NewOpenAIStageObserver(generator StageGuidanceGenerator) (*OpenAIStageObserver, error) {
	if generator == nil {
		return nil, errors.New("stage guidance generator is required")
	}
	return &OpenAIStageObserver{generator: generator}, nil
}

// OnStageCompleted builds a stage-specific prompt and enriches the stage output
// with a side-by-side analyst guidance block from the model.
func (o *OpenAIStageObserver) OnStageCompleted(ctx context.Context, input ThirdPartyInput, result *ToolResult) error {
	if result == nil {
		return errors.New("tool result is required")
	}

	instructions, userPrompt, err := BuildStagePrompt(input, *result)
	if err != nil {
		return fmt.Errorf("build stage prompt: %w", err)
	}

	guidance, err := o.generator.GenerateStageGuidance(ctx, instructions, userPrompt)
	if err != nil {
		return fmt.Errorf("generate stage guidance: %w", err)
	}

	if result.Output == nil {
		result.Output = map[string]any{}
	}
	result.Output["agent_guidance"] = map[string]any{
		"stage":        input.Stage,
		"instructions": instructions,
		"guidance":     guidance,
	}

	return nil
}

type openAIResponsesRequest struct {
	Model        string               `json:"model"`
	Instructions string               `json:"instructions,omitempty"`
	Input        []openAIInputMessage `json:"input"`
}

type openAIInputMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponsesResponse struct {
	OutputText string                     `json:"output_text"`
	Output     []openAIOutputResponseItem `json:"output"`
}

type openAIOutputResponseItem struct {
	Type    string                     `json:"type"`
	Role    string                     `json:"role"`
	Content []openAIOutputContentBlock `json:"content"`
}

type openAIOutputContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// extractOutputText supports both output_text shortcut and output message blocks.
func extractOutputText(response openAIResponsesResponse) string {
	if strings.TrimSpace(response.OutputText) != "" {
		return response.OutputText
	}

	texts := make([]string, 0)
	for _, item := range response.Output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
				texts = append(texts, content.Text)
			}
		}
	}

	return strings.TrimSpace(strings.Join(texts, "\n"))
}
