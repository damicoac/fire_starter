# AGENTS.md

## Repository Overview

- Language: Go
- Module path: `fire_starter` (`go.mod`)
- Go version: `1.24.2`
- Primary executable: `cmd/fire_starter/main.go`
- Primary domain packages:
  - `src/matrix/` (decision models, tool registry, executor logic, runloop)
  - `src/database/` (SQLite audit logging + reinforcement scoring)

## Directory Structure (Observed)

- `src/`
  - `matrix/`
    - `agent.go`
    - `decisions.json`
    - `executor.go`
    - `models.go`
    - `real_executor.go`
    - `runloop.go`
    - `tool_registry.go`
  - `database/`
    - `audit_logging.go`
    - `reinforcement_learning.go`
- `cmd/fire_starter/`
  - `main.go`
- `README.md`
- `test.md`
- `docs/notes.md`
- `go.mod`
- `go.sum`

## Rule / Instruction Files Found

Searched for:

- `.cursor/rules/*.md`
- `.cursorrules`
- `.github/copilot-instructions.md`
- `claude.md`
- `agents.md`

None of the above were found.

## Essential Commands

From repository root:

### Run server (no build)

```bash
go run ./src/http-server
```

### Build binary

```bash
go build -o fire_starter-server ./cmd/fire_starter
```

### Run built binary

```bash
./fire_starter-server
```

### Dependency tidy

```bash
go mod tidy
```

### Test command

No custom test harness was found (no Makefile/Taskfile/CI workflow). Use:

```bash
go test ./...
```

### Manual API checks (documented)

List tools:

```bash
curl -s http://localhost:8080/tools | jq
```

Execute by identifier:

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"0000","payload":{"ip":"192.168.1.100","url":"http://192.168.1.100"}}'
```

Execute by tool name:

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"decision_port_scanning","payload":{"target":"192.168.1.100"}}'
```

## How Execution Is Wired

### Decision source of truth

- `src/matrix/decisions.json` contains the decision list used by both tool listing and execution.
- `cmd/fire_starter/main.go` loads this file at startup.

### HTTP server behavior

- `GET /tools` returns tool definitions generated from the decision matrix.
- `POST /execute` accepts either:
  - `identifier`, or
  - `tool_name`
- Response streaming is NDJSON (`application/x-ndjson`) with progress updates and a final `done=true` payload.

### Tool generation pattern

- `src/matrix/tool_registry.go` derives a tool from each decision.
- Tool name is normalized from `Decision.Technique` and prefixed as `decision_<normalized_technique>`.
- Tools are sorted by `Identifier`.

### Execution mapping pattern

- `src/matrix/real_executor.go` maps decision technique text to stage strings via `MapTechniqueToStage`.
- Default stage fallback is `application-mapping.explore` when no mapping matches.

## Code Conventions and Patterns (Observed)

- Go packages use short lowercase names (`matrix`, `database`).
- Error handling wraps context with `fmt.Errorf("...: %w", err)`.
- Constructors are `NewX` style (e.g., `NewRealExecutor`, `NewToolRegistry`, `NewSQLiteAuditLogger`).
- JSON contracts use struct tags and `map[string]any` for flexible payloads.
- SQLite implementations:
  - validate required input fields before writes
  - initialize schema in constructor
  - provide `Close()` methods

## Database Components

### Audit logger (`src/database/audit_logging.go`)

- Driver: `modernc.org/sqlite`
- Default DB path when blank: `fire_starter_audit.db`
- Table: `audit_events`
- Uniqueness: `(run_id, sequence)`

### Reinforcement learner (`src/database/reinforcement_learning.go`)

- Driver: `modernc.org/sqlite`
- Default DB path when blank: `fire_starter_reinforcement.db`
- Tables:
  - `reinforcement_transition_events`
  - `reinforcement_transition_scores`
- Ranking favors: success rate, then total reward, then attempts.

## Testing Status

- No `*_test.go` files were found.
- No CI workflow files were found under `.github/workflows`.
- `test.md` provides manual API test commands (including negative cases).

## Important Gotchas

1. Decision updates need mapping updates:
   - Adding a new decision technique in `src/matrix/decisions.json` may require updating `MapTechniqueToStage` in `src/matrix/real_executor.go`.
2. RealExecutor silently backfills payload defaults when keys are missing:
   - `ip = 127.0.0.1`
   - `url = http://127.0.0.1`
   - `target = 127.0.0.1`
3. `cmd/fire_starter/main.go` attempts a fallback path for `decisions.json` if `src/matrix/decisions.json` is not found, so startup path assumptions differ by working directory.
4. `src/matrix/runloop.go` is interactive console flow, while `cmd/fire_starter/main.go` is the active network entrypoint for streaming API execution.

## Current Project Notes

From `docs/notes.md`:

- Building runloop from the decision matrix.
- Laying groundwork for an MCP version to integrate with Crush.
- Intention to build modules incrementally, potentially via a module framework first.
