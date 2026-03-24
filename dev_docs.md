# Blackwater Decision Tree Application - Developer Docs

## What this application is

Blackwater is a Go-based decision-tree engine for orchestrating staged security testing workflows. It models testing as a sequence of stage nodes that transform input payloads, emit tool-call metadata, and decide the next stage.

Core package: `decisiontree/`.

## High-level flow

1. Execution starts with `Tree.Run(...)` or `Tree.RunWithObserver(...)` using an initial `ThirdPartyInput`:
   - `Stage string`
   - `Payload map[string]any`
2. The tree selects a node/tool whose condition matches the current stage (`Tree.SelectTool`).
3. That node executes and returns `ToolResult`:
   - `ToolName`
   - `Calls []ToolCall` (tool/function/purpose trace)
   - `Output map[string]any`
4. A resolver converts output into the next input (`DefaultNextInputResolver` by default).
5. The loop continues while `continue=true`; it stops when `continue=false`.

## Node transition contract

Nodes communicate transitions through `ToolResult.Output` keys:

- `next_stage` (`string`): next stage identifier
- `next_payload` (`map[string]any`): payload passed forward
- `continue` (`bool`): whether to keep looping

`DefaultNextInputResolver` behavior:

- Missing/non-bool `continue` defaults to `false` (flow ends).
- Missing/non-map `next_payload` defaults to an empty payload.

## Architecture and key files

- `decisiontree/decision_tree.go`
  - Core types and validation (`Tree`, `ToolDefinition`, `ThirdPartyInput`, `ToolResult`)
- `decisiontree/run_loop.go`
  - Main execution loop and optional stage observer hook
- `decisiontree/registry.go`
  - Global registry for nodes/tools (`RegisterNode`, `MustRegisterNode`, `RegisteredTools`)
- `decisiontree/resolver.go`
  - Default resolver implementation
- `decisiontree/payload_helpers.go`
  - Helpers: `requireString`, `getBool`, `copyPayload`
- `decisiontree/*_stages.go`
  - Stage constants grouped by module
- `decisiontree/node_*.go`
  - One file per stage node implementation

## Modules currently implemented

### 1) Target intake/classification

- `target.received`
- `target.classify`

Validates target IP and branches into API testing when `has_api=true`.

### 2) API testing pipeline

Stages (`api-testing.*`):

- `recon`
- `access-control`
- `rate-limit`
- `injection`
- `graphql`
- `fuzzing`
- `complete`

Runs sequentially once entered, with payload flags marking completed checks.

### 3) Application mapping pipeline

Stages (`application-mapping.*`):

- `explore`
- `entry-points`
- `metadata-review`
- `attack-surface`
- `complete`

Includes branch behavior for expanded prioritization when requested by payload flags.

### 4) Active testing pipeline

Stages (`active-testing.*`):

- `access-control`
- `business-logic`
- `input-probing`
- `xss`
- `injection`
- `error-handling`
- `configuration-checks`
- `complete`

Includes conditional branch behavior (for example, skipping XSS stage via payload controls).

## How nodes are wired

Each node file follows this pattern:

1. `init()` registers the node with `MustRegisterNode(...)`
2. `isXStage(...)` matches on `input.Stage`
3. `runX(...)` validates inputs, updates payload, records `Calls`, sets transition output

`NewTreeFromRegistry(...)` builds a runnable tree from all registered nodes.

## Observability and model-guidance extension

`RunWithObserver(...)` accepts a `StageObserver` that runs after each stage completes.

OpenAI integration (`decisiontree/openai_integration.go`) provides:

- `OpenAIResponsesClient`: HTTP client for OpenAI Responses API
- `OpenAIStageObserver`: builds stage prompts and injects `agent_guidance` into stage output

Prompt construction logic is in `decisiontree/agent_prompts.go`, with stage-specific guidance plans by stage prefix (`api-testing.`, `application-mapping.`, `active-testing.`).

## Testing strategy

Tests are in:

- `decisiontree/decision_tree_test.go`
- `decisiontree/agent_prompts_test.go`
- `decisiontree/openai_integration_test.go`

Coverage includes:

- Constructor and validation rules
- Tool selection behavior
- Loop/resolver/error propagation
- Full flow execution and branch paths
- Invalid payload handling
- Registry isolation (`withTemporaryRegistry`)
- OpenAI client request/response behavior with `httptest`

Run tests with:

```bash
go test ./...
```

## Important implementation details

- Node registry is global mutable state guarded by a mutex.
- Stage matching is first-match over registered tools; overlapping conditions can cause routing surprises.
- Payload is dynamic (`map[string]any`), so nodes should validate required fields and copy payload before mutation.
- Missing `continue=true` in a node output will terminate flow under the default resolver.

## Typical lifecycle for adding a new stage/module

1. Add stage constants in the relevant `*_stages.go` file.
2. Create one `node_*.go` file per stage.
3. Register each node in `init()`.
4. Use payload helpers for validation and mutation.
5. Return transition keys in `ToolResult.Output`.
6. Add tests for full path, branching, and invalid payload.
7. Run `go test ./...`.
