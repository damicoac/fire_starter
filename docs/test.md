# Test and Verification Guide

## 1) Run full automated tests

```bash
go test ./...
```

## 2) Run focused package tests

```bash
go test ./src/agent ./src/matrix ./src/modules
```

## 3) High-value behavioral checks covered by tests

### Agent workflow (`src/agent/workflow_test.go`)

- Recon tools remain available outside recon phase (always-recon exception).
- Phase advancement gating requires evidence (e.g., discovered targets, findings).
- Final submit gating requires required phase coverage and vulnerability evidence.
- Already-executed tools receive scoring penalties.

### Matrix execution (`src/matrix/real_executor_test.go`)

- Technique-to-phase mapping coverage (`MapTechniqueToStage`).
- Tool lookup behavior for missing identifiers/tool names.
- Payload normalization helpers (`payloadString`, `payloadInt`) across edge inputs.
- Target validation and cross-population behavior for `ip`/`url`.
- Representative module execution paths (including OOB-enabled SSTI path).

### Knowledge graph (`src/matrix/knowledge_graph_test.go`)

- Signal extraction from JSON and malformed text outputs.
- Deduplication logic for cookies/tokens and entities.
- Scoring updates for repeated discoveries and open-port enrichment.
- Concurrent update safety under goroutines.

## 4) Manual smoke test (CLI)

Run a short verbose engagement:

```bash
go run ./cmd/fire_starter -target http://127.0.0.1 -max-iters 3 -verbose
```

Expected behavior:

- Startup log includes provider/model/target.
- Iteration logs show tool selection and execution attempts.
- If completion criteria are not met within `max-iters`, command exits with `max iterations reached without calling 'submit'`.

## 5) Environment checks

- Go version must satisfy `go.mod` (`go 1.26.2`).
- Provider setup must match the selected `-provider`.

Check Go version:

```bash
go version
```

## 6) Regression checklist for documentation-related changes

When docs are updated, verify:

- Commands reference `./cmd/fire_starter` (not deprecated/removed paths).
- Flag names in docs match `cmd/fire_starter/main.go`.
- Testing command remains `go test ./...`.
- Cross-file references (`README.md`, `docs/quick_start.md`, `docs/notes.md`) are consistent.
