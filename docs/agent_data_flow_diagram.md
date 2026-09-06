# Agent Data Flow and Architecture

Fire Starter uses a CLI-first orchestration model centered around a shared knowledge graph plus SQLite-backed persistence. The entrypoint in `cmd/fire_starter/main.go` launches the Bubble Tea interface, initializes the agent workflow, and streams execution state into the UI while the orchestration layer evaluates targets.

## High-level data flow

```mermaid
flowchart TD
    CLI[CLI Entrypoint]
    TUI[Bubble Tea TUI]
    Orchestrator[RunAgent Orchestrator]
    KnowledgeGraph[(Knowledge Graph\nIn-Memory State)]
    SQLite[(SQLite DB\nfire_starter.db)]
    Report[Markdown Report\nfire_starter_report.md]

    subgraph TargetLoop [Per-Target Agent Loop]
        Prompt[Prompt Assembly]
        LLM[Language Model]
        Tools[Registered Module Tools]
        Helper[Helper Sub-Agent]
    end

    CLI --> TUI
    CLI --> Orchestrator
    Orchestrator --> KnowledgeGraph
    Orchestrator --> SQLite
    Orchestrator --> TargetLoop
    KnowledgeGraph -. snapshot .-> Prompt
    Prompt --> LLM
    LLM --> Tools
    Tools --> KnowledgeGraph
    Tools --> SQLite
    LLM --> Helper
    Helper --> KnowledgeGraph
    Helper --> SQLite
    Orchestrator --> Report
    KnowledgeGraph --> TUI
    Orchestrator --> TUI
```

## 1. Entrypoint and config loading

`cmd/fire_starter/main.go` performs the startup sequence:

- creates the default config
- loads a JSON config file when `-config` is provided
- applies CLI flag overrides
- validates that a target exists
- starts the Bubble Tea program
- launches `agent.RunAgent(...)` in a goroutine

The current user-facing flags are:

- `-config`
- `-target`
- `-provider`
- `-model`
- `-base-url`
- `-max-iters`
- `-verbose`
- `-efficiency`

## 2. Orchestration layer

`src/agent/workflow.go` is the control plane.

It is responsible for:

- provider initialization for OpenAI, Anthropic, Gemini, and local OpenAI-compatible endpoints
- target normalization and scope enforcement
- loading and scoring tools from the decision matrix
- driving per-target execution phases
- persisting vulnerabilities and execution logs
- generating the final markdown report

Efficiency mode is enabled by default. When left on, the target agent is allowed to aggressively skip low-value targets early.

## 3. Tool exposure and execution

`src/matrix/tool_registry.go` converts decision definitions into model-callable tools.

`src/matrix/real_executor.go` then:

- resolves a tool back to its technique
- normalizes payload fields such as `ip` and `url`
- looks up a registered module factory in `src/modules/core`
- executes the module
- attaches proof-of-concept evidence captured via `BaseModule.RecordPoC(...)`

## 4. Knowledge graph, session management, and persistence

`src/matrix/knowledge_graph.go` tracks the evolving engagement state, including:

- discovered targets
- open ports and services
- session credentials, auth tokens, and automated cookie jar state
- vulnerability summaries and status details
- target phase transitions

`src/matrix/db.go` persists execution logs and vulnerability records to `fire_starter.db`.

Vulnerability records use an explicit lifecycle status:

- `candidate`: unconfirmed signal that still needs helper validation
- `confirmed`: validated security issue eligible for the main findings section
- `disproven`: tested signal that should not appear as a report finding
- `informational`: validated observation that should be appended separately from vulnerabilities

Severity is tracked separately as `critical`, `high`, `medium`, `low`, `informational`, or `unknown`. The old `processed` lifecycle field has been removed; `status` is the lifecycle source of truth.

This split keeps fast iteration state and session tokens in memory while still retaining durable evidence on disk.

## 5. Helper sub-agent flow

During deeper validation, the target loop can spawn a focused helper sub-agent for a specific finding. That helper gets the target, finding summary, available tools, session cookies/tokens, and current graph context so it can refine exploitability evidence and update the persistent vulnerability record.

## 6. Report generation

At the end of a run, the workflow:

1. reads persisted vulnerability records
2. includes only `confirmed` records in the main vulnerability summary with their separate severity
3. appends `informational` records in a separate report section
4. excludes `candidate` and `disproven` records from report findings
5. asks the configured model for a narrative report when possible
6. falls back to a minimal markdown report if report generation fails
7. appends a JSON knowledge graph dump
8. writes the result to `fire_starter_report.md`

## 7. TUI data flow

The TUI in `src/tui` receives two message streams:

- execution logs written through the program writer
- knowledge graph updates serialized to JSON

The UI provides a 3-tab layout (Execution Logs, Site Map, Knowledge Base & Target Inspector) with live log category filtering (`All`, `Modules`, `Agent`, `Errors`), summary collapsing, and interactive target inspection.
