package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/log"
)

var (
	ErrNoMatchingTool = errors.New("no matching tool found")
	ErrUnknownTool    = errors.New("unknown tool")
)

type ThirdPartyInput struct {
	Stage   string
	Payload map[string]any
}

type ToolResult struct {
	ToolName string
	Output   map[string]any
	Calls    []ToolCall
}

type ToolFunc func(ctx context.Context, input ThirdPartyInput) (ToolResult, error)

type ToolCondition func(input ThirdPartyInput) bool

type ToolDefinition struct {
	Name        string
	Description string
	Condition   ToolCondition
	Run         ToolFunc
}

type NextInputResolver func(ctx context.Context, result ToolResult) (next ThirdPartyInput, continueFlow bool, err error)

// ToolDescriptor is the minimal tool metadata exposed to LLM routing.
type ToolDescriptor struct {
	Name        string
	Description string
}

type Tree struct {
	tools  []ToolDefinition
	logger *log.Logger
}

func NewTree(logger *log.Logger, tools []ToolDefinition) (*Tree, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if len(tools) == 0 {
		return nil, errors.New("at least one tool is required")
	}

	for i, tool := range tools {
		if err := validateTool(tool); err != nil {
			return nil, fmt.Errorf("tool at index %d is invalid: %w", i, err)
		}
	}

	return &Tree{tools: tools, logger: logger}, nil
}

func NewTreeFromRegistry(logger *log.Logger) (*Tree, error) {
	return NewTree(logger, RegisteredTools())
}

func (t *Tree) SelectTool(input ThirdPartyInput) (ToolDefinition, error) {
	for _, tool := range t.tools {
		if tool.Condition(input) {
			return tool, nil
		}
	}

	return ToolDefinition{}, ErrNoMatchingTool
}

// SelectToolByName resolves a tool definition by its registered name.
func (t *Tree) SelectToolByName(name string) (ToolDefinition, error) {
	for _, tool := range t.tools {
		if tool.Name == name {
			return tool, nil
		}
	}
	return ToolDefinition{}, fmt.Errorf("%w: %s", ErrUnknownTool, name)
}

// ToolCatalog returns a normalized list of available tools for LLM planning.
func (t *Tree) ToolCatalog() []ToolDescriptor {
	catalog := make([]ToolDescriptor, 0, len(t.tools))
	for _, tool := range t.tools {
		description := tool.Description
		if description == "" {
			description = fmt.Sprintf("tool %s", tool.Name)
		}
		catalog = append(catalog, ToolDescriptor{
			Name:        tool.Name,
			Description: description,
		})
	}
	return catalog
}

func validateTool(tool ToolDefinition) error {
	if tool.Name == "" {
		return errors.New("empty tool name")
	}
	if tool.Condition == nil {
		return fmt.Errorf("tool %q has no condition", tool.Name)
	}
	if tool.Run == nil {
		return fmt.Errorf("tool %q has no run function", tool.Name)
	}
	return nil
}
