// File overview:
// Core engine data contracts and tool-selection logic. It defines canonical runtime structures so every module follows the same input/output shape and selection behavior.

package core

import (
	"context"
	"errors"
	"fmt"

	"blackwater/decisiontree/database"

	"github.com/charmbracelet/log"
)

var (
	ErrNoMatchingTool = errors.New("no matching tool found")
	ErrUnknownTool    = errors.New("unknown tool")
)

// ThirdPartyInput is the canonical stage invocation envelope.
// Keeping stage and payload together lets every node share one contract,
// which reduces adapter code and makes stage transitions composable.
type ThirdPartyInput struct {
	Stage   string
	Payload map[string]any
}

// ToolResult is the canonical output contract from any stage node.
// It intentionally includes both machine-routing output and human/audit trace
// calls so orchestration and reporting can use the same artifact.
type ToolResult struct {
	ToolName   string
	Output     map[string]any
	Calls      []ToolCall
	Executions []ToolExecution
}

// ToolFunc is the execution unit for a stage.
// This function type keeps stage behavior swappable for tests and integration
// while preserving context-aware cancellation and deadlines.
type ToolFunc func(ctx context.Context, input ThirdPartyInput) (ToolResult, error)

// ToolCondition maps input state to node eligibility.
// Separating matching from execution keeps routing logic declarative and allows
// new stages to register without modifying central switch statements.
type ToolCondition func(input ThirdPartyInput) bool

// ToolDefinition binds stage identity, selection logic, and execution logic.
// This struct exists so registry/tree code can reason about nodes uniformly,
// regardless of feature module boundaries.
type ToolDefinition struct {
	Name        string
	Description string
	Condition   ToolCondition
	Run         ToolFunc
}

// NextInputResolver translates tool output into the next loop input.
// This indirection allows different transition policies (default, strict,
// experimental) without rewriting stage node implementations.
type NextInputResolver func(ctx context.Context, result ToolResult) (next ThirdPartyInput, continueFlow bool, err error)

// ToolDescriptor is the minimal tool metadata exposed to LLM routing.
type ToolDescriptor struct {
	Name        string
	Description string
}

// Tree holds the ordered tool catalog and shared logger.
// Order matters because first-match selection is used to keep precedence
// deterministic when conditions overlap.
type Tree struct {
	tools       []ToolDefinition
	logger      *log.Logger
	auditLogger database.AuditLogger
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

func NewTreeWithAuditLogger(logger *log.Logger, tools []ToolDefinition, auditLogger database.AuditLogger) (*Tree, error) {
	tree, err := NewTree(logger, tools)
	if err != nil {
		return nil, err
	}
	tree.auditLogger = auditLogger
	return tree, nil
}

func (t *Tree) SetAuditLogger(auditLogger database.AuditLogger) {
	if t == nil {
		return
	}
	t.auditLogger = auditLogger
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
