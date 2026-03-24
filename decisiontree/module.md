# Decision Tree Module Guide

This guide explains how to add new modules to the decision-tree engine with the current file-per-node pattern.

## Architecture

A module is a sequence of **stages**. Each stage is implemented as a **node file** that registers itself.

Execution model:
1. `Tree.Run` selects a node by `input.Stage`.
2. Node runs and returns `ToolResult`.
3. Resolver (`DefaultNextInputResolver`) reads `ToolResult.Output`.
4. Loop continues using `next_stage` and `next_payload` until `continue=false`.

Core files:
- `decision_tree.go`: types and tree selection.
- `run_loop.go`: execution loop.
- `registry.go`: node registration (`MustRegisterNode`, `RegisterNode`).
- `resolver.go`: transition resolver.
- `tool_call.go`: tool/function metadata model.

## Node Contract

Each node file must provide:
- `init()` that calls `MustRegisterNode(...)`
- a stage matcher: `func isXStage(input ThirdPartyInput) bool`
- an executor: `func runX(ctx context.Context, input ThirdPartyInput) (ToolResult, error)`

`ToolResult` fields:
- `ToolName`: logical node/tool identifier.
- `Calls`: list of tool/function calls this stage performs.
- `Output`: transition payload map.

Required `Output` keys for transitions:
- `"next_stage"` (string): next stage name (optional if stopping).
- `"next_payload"` (map[string]any): payload for next stage.
- `"continue"` (bool): continue loop (`true`) or stop (`false`).

## Create a New Module

## 1) Add stage constants

Create a stage constants file (or extend an existing one):

```go
package decisiontree

const (
	stageMyModuleStart    = "my-module.start"
	stageMyModuleValidate = "my-module.validate"
	stageMyModuleComplete = "my-module.complete"
)
```

## 2) Add one file per node

Use this template for each stage:

```go
package decisiontree

import "context"

func init() {
	MustRegisterNode(stageMyModuleStart, isMyModuleStartStage, runMyModuleStart)
}

func isMyModuleStartStage(input ThirdPartyInput) bool {
	return input.Stage == stageMyModuleStart
}

func runMyModuleStart(ctx context.Context, input ThirdPartyInput) (ToolResult, error) {
	_ = ctx

	target, err := requireString(input.Payload, "target")
	if err != nil {
		return ToolResult{}, err
	}

	nextPayload := copyPayload(input.Payload)
	nextPayload["target"] = target
	nextPayload["validated"] = true

	return ToolResult{
		ToolName: stageMyModuleStart,
		Calls: []ToolCall{
			{Tool: "validator", Function: "ValidateTarget", Purpose: "validate target input"},
		},
		Output: map[string]any{
			"next_stage":   stageMyModuleValidate,
			"next_payload": nextPayload,
			"continue":     true,
		},
	}, nil
}
```

## 3) Add branching logic when needed

Branch by setting `next_stage` conditionally:

```go
nextStage := stageMyModuleComplete
if getBool(input.Payload, "run_deep_checks") {
	nextStage = stageMyModuleValidate
}
```

## 4) Add a terminal node

Terminal nodes should return `continue=false`:

```go
return ToolResult{
	ToolName: stageMyModuleComplete,
	Calls: []ToolCall{
		{Tool: "reporter", Function: "Summarize", Purpose: "create module summary"},
	},
	Output: map[string]any{
		"next_payload": nextPayload,
		"continue":     false,
	},
}, nil
```

## 5) Run through `NewTreeFromRegistry`

Use:

```go
tree, err := NewTreeFromRegistry(logger)
```

This auto-loads all node files that called `MustRegisterNode` in `init()`.

## Testing Requirements

Add tests for:
- successful full module path,
- branch path(s),
- invalid payload handling.

Pattern:

```go
err = tree.Run(context.Background(), ThirdPartyInput{
	Stage: stageMyModuleStart,
	Payload: map[string]any{
		"target": "example",
	},
}, DefaultNextInputResolver)
```

Current command:

```bash
go test ./...
```

## Conventions

- Stage naming: `<module>.<stage>` (example: `api-testing.recon`).
- One stage per file for easy module growth.
- Keep node logic focused on stage decisions and transition payloads.
- Use `requireString`, `getBool`, and `copyPayload` helpers for payload handling.
- Always include `Calls` so downstream reporting can show tool/function history.

## API-Testing Module Reference

The existing API-testing implementation is the reference:
- Stage constants: `api_testing_stages.go`
- Entry/classification nodes: `node_target_received.go`, `node_target_classify.go`
- API path nodes:
  - `node_api_recon.go`
  - `node_api_access_control.go`
  - `node_api_rate_limit.go`
  - `node_api_injection.go`
  - `node_api_graphql.go`
  - `node_api_fuzzing.go`
  - `node_api_complete.go`

Use this layout as the standard for future modules.
