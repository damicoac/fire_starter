# Test and Verification Guide

This guide documents the project verification workflow and the checks worth running after code or documentation changes.

## 1. Full automated test suite

```bash
go test ./...
```

## 2. Focused package suites

```bash
go test ./src/agent ./src/matrix ./src/modules/...
```

## 3. CI expectations

GitHub Actions runs:

- Go `1.26.2`
- `go test ./...`
- `golangci-lint`

If local results differ from CI, confirm your Go version first.

## 4. High-value behavioral coverage

### Agent workflow (`src/agent/workflow.go`)

Tests cover behavior such as:

- Provider initialization and control-loop execution paths
- Recon-tool availability outside pure recon scoring
- Phase advancement gating based on discovered evidence
- Submission and target-completion guardrails
- Efficiency-mode early-exit behavior

### Matrix execution (`src/matrix/real_executor.go`)

Tests cover behavior such as:

- Technique-to-phase mapping
- Tool lookup by identifier and tool name
- Payload normalization helpers for strings and integers
- Automatic `ip`/`url` cross-population
- Module execution and result shaping
- Proof-of-concept propagation into `reproduction_steps`

### Knowledge graph and database (`src/matrix/knowledge_graph.go`, `src/matrix/db.go`)

Tests cover behavior such as:

- Extraction from structured JSON and malformed text
- Deduplication of tokens, entities, and findings
- Vulnerability persistence and processed-state handling
- Concurrent update safety
- Scope filtering for newly discovered assets

### Modules (`src/modules/core`)

Module tests validate representative detection and execution paths across the built-in technique set.

## 5. Manual smoke test

Run a short engagement:

```bash
go run ./cmd/fire_starter -target http://127.0.0.1 -max-iters 3 -verbose
```

Expected outcomes:

- The TUI starts successfully.
- Logs show provider/model/target startup details.
- The agent attempts tool selection and execution.
- The run writes report/database artifacts when it finishes.

## 6. Environment checks

Verify the Go version:

```bash
go version
```

The project requires `go 1.26.2` or newer.

## 7. Documentation regression checklist

When docs or website content changes, verify that:

- Commands reference `./cmd/fire_starter`.
- Flag names match `cmd/fire_starter/main.go`.
- Config examples include current fields such as `efficiency_mode` and `target_domains` when relevant.
- Output artifact names match the code: `fire_starter_report.md` and `fire_starter.db`.
- Module-development docs reference `src/modules/core`, not unsupported runtime paths.
- Website copy matches the current CLI-first architecture.
