# AGENTS.md

## Repository Overview

- Language: Go (`go.mod` module name: `blackwater`, Go version `1.23.0`).
- Primary package: `decisiontree/`.
- This repository implements a stage-driven security testing decision tree with node registration and looped stage transitions.

## What Exists (and What Does Not)

- Observed source code is under `decisiontree/`.
- No `Makefile`, no CI workflow files in `.github/workflows/`, and no additional rule files were found (`.cursorrules`, `.cursor/rules/*.md`, `.github/copilot-instructions.md`, `claude.md`, `agents.md`).
- No app/server entrypoint (such as `main.go`) was found in the scanned tree.

## Essential Commands

Use the commands that are explicitly present in repository docs/tests:

```bash
go test ./...
```

This command is documented in `decisiontree/module.md` and matches the current package test layout.

## Code Organization

Top-level:

- `go.mod`, `go.sum`
- `decisiontree/` (all observed implementation + tests)

Inside `decisiontree/`:

- Core engine:
  - `decision_tree.go`: core types (`Tree`, `ToolDefinition`, `ToolResult`, `ThirdPartyInput`) and tree construction/validation.
  - `run_loop.go`: runtime loop (`Run`, `RunWithObserver`) and `StageObserver` hook.
  - `registry.go`: global registration API (`RegisterNode`, `MustRegisterNode`, `RegisteredTools`).
  - `resolver.go`: default transition resolver (`DefaultNextInputResolver`).
  - `payload_helpers.go`: payload helpers (`requireString`, `getBool`, `copyPayload`).
  - `tool_call.go`: `ToolCall` model.
- Stage constants:
  - `api_testing_stages.go`
  - `application_mapping_stages.go`
  - `active_testing_stages.go`
- Node implementations (file-per-stage pattern):
  - `node_target_*`, `node_api_*`, `node_application_mapping_*`, `node_active_testing_*`.
- Prompt/model integration:
  - `agent_prompts.go`: stage-aware prompt planning and prompt assembly.
  - `openai_integration.go`: OpenAI Responses API client + stage observer.
- Tests:
  - `decision_tree_test.go`
  - `agent_prompts_test.go`
  - `openai_integration_test.go`
- Internal module guide:
  - `module.md`

## Core Runtime Pattern

1. Input enters with a `Stage` string and `Payload` map (`ThirdPartyInput`).
2. `Tree.SelectTool` chooses the first registered node whose `Condition` matches.
3. Node `Run` returns `ToolResult` with `ToolName`, `Calls`, and `Output`.
4. Resolver translates `ToolResult.Output` into next input.
5. Loop continues while resolver returns `continue=true`.

Transition contract (as used across nodes and resolver):

- `Output["next_stage"]` (string)
- `Output["next_payload"]` (`map[string]any`)
- `Output["continue"]` (bool)

Important behavior from `resolver.go`:

- If `continue` is absent, flow defaults to `false` (stops).
- If `next_payload` is absent/wrong type, payload defaults to empty map.

## Node Authoring Conventions

The project follows a one-file-per-stage node pattern:

- Register in `init()` via `MustRegisterNode(stageConst, matcher, runner)`.
- Matcher shape: `func isXStage(input ThirdPartyInput) bool`.
- Runner shape: `func runX(ctx context.Context, input ThirdPartyInput) (ToolResult, error)`.

Observed style conventions:

- Stage naming uses dotted, prefixed identifiers such as:
  - `api-testing.recon`
  - `application-mapping.explore`
  - `active-testing.access-control`
- Nodes typically:
  - validate required payload fields with `requireString`,
  - clone input payload with `copyPayload`,
  - set stage-completion flags on payload,
  - emit `Calls` metadata for traceability,
  - set transition keys in `Output`.

## Testing Patterns

Current tests are table-driven or flow-driven and focus on:

- constructor/validation behavior,
- tool selection behavior,
- error propagation from tool execution and resolver,
- full multi-stage flow execution,
- branch behavior (e.g., API presence branch, XSS skip branch),
- invalid payload handling,
- registry isolation in tests (`withTemporaryRegistry` helper),
- OpenAI client request/response behavior via `httptest`.

When adding/changing stages, mirror existing tests by covering:

- happy-path full flow,
- branch path(s),
- invalid payload/error path.

## OpenAI Integration Notes

From `openai_integration.go`:

- Default endpoint: `https://api.openai.com/v1/responses`.
- Env-based constructor requires `OPENAI_API_KEY`.
- `NewOpenAIResponsesClient` also requires non-empty model name.
- `OpenAIStageObserver` injects `agent_guidance` into `ToolResult.Output` after each stage.

## Gotchas / Non-obvious Details

- Registration is global mutable state (`registeredSet`), protected by mutex; tests may need registry reset/isolation.
- `NewTreeFromRegistry` uses current global registry contents; missing `init()` registration means stages are not discoverable.
- `Tree.SelectTool` returns the first matching tool; overlapping conditions can cause precedence issues.
- `DefaultNextInputResolver` does not enforce required transition keys; malformed node output can silently stop flow (`continue=false` default).
- Payload is `map[string]any`; copy before mutation (`copyPayload`) to preserve prior state and avoid side effects.

## Practical Workflow for Future Agents

1. Add or adjust stage constants in the appropriate `*_stages.go` file.
2. Implement one node file per new stage with `init()` registration.
3. Ensure node `Output` includes transition keys and `Calls` metadata.
4. Add/extend tests in `decisiontree/*_test.go` for full path + branch + invalid payload.
5. Run:

```bash
go test ./...
```

6. If prompt/model behavior changes, update both `agent_prompts_test.go` and `openai_integration_test.go` accordingly.
