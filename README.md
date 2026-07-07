<div align="center">
  <h1>🔥 Fire Starter 🔥</h1>
  <p><strong>Autonomous security assessment agent for authorized environments</strong></p>

  <p>
    <a href="https://github.com/damicoac/fire_starter/actions/workflows/ci.yml"><img src="https://github.com/damicoac/fire_starter/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
    <a href="https://github.com/damicoac/fire_starter/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  </p>
</div>

---

Fire Starter is a Go-based autonomous security assessment agent built for authorized testing. It combines a phase-aware agent loop, a shared knowledge graph, modular test execution, a Bubble Tea terminal UI, and report generation that leaves both an executive summary and reproducible technical evidence on disk.

## Key features

- Phase-aware autonomous workflow driven by `src/matrix/decisions.json`
- Bubble Tea TUI with live execution logs and a knowledge graph sidebar
- Modular Go execution layer with self-registering module factories in `src/modules/core`
- Shared knowledge graph that tracks targets, ports, credentials, tokens, and findings
- SQLite-backed vulnerability logging in `fire_starter.db`
- Markdown report output in `fire_starter_report.md`
- Configurable provider support for OpenAI, Anthropic, Gemini, and local OpenAI-compatible endpoints
- Optional efficiency mode for aggressively triaging low-value targets

## Safety and scope

Use this project only against systems you own or are explicitly authorized to assess.
The agent performs active security testing and should be run only within approved rules of engagement.

## Install and build

### Prerequisites

- Go `1.26.2` or newer
- Provider credentials for the selected backend:
  - `OPENAI_API_KEY` for `-provider openai`
  - `ANTHROPIC_API_KEY` for `-provider anthropic`
  - `GEMINI_API_KEY` for `-provider gemini`
- No cloud credential is required when using a local OpenAI-compatible endpoint via `-provider local`

### Build

```bash
git clone https://github.com/damicoac/fire_starter.git
cd fire_starter
go mod tidy
go build -o fire_starter ./cmd/fire_starter
```

## Run Fire Starter

### Minimal run

```bash
./fire_starter -target http://127.0.0.1
```

### Explicit provider and iteration settings

```bash
./fire_starter \
  -target http://127.0.0.1 \
  -provider openai \
  -model gpt-4o \
  -max-iters 15 \
  -verbose
```

### With a local OpenAI-compatible endpoint

```bash
./fire_starter \
  -target http://127.0.0.1 \
  -provider local \
  -model llama3.1 \
  -base-url http://127.0.0.1:11434
```

## CLI flags

- `-config <path>`: load JSON configuration from disk
- `-target <ip-or-url>`: target to assess
- `-provider <openai|anthropic|gemini|local>`: select the language model provider
- `-model <model-id>`: provider model identifier
- `-base-url <url>`: custom provider base URL, mainly for local or proxied OpenAI-compatible endpoints
- `-max-iters <int>`: maximum control-loop iterations
- `-verbose`: enable debug logging
- `-efficiency=false`: disable aggressive target triage; efficiency mode defaults to enabled

## TUI navigation

The interface has a log pane and a knowledge graph pane.

- `Tab`: switch focus between panes
- `Up` / `Down` or `k` / `j`: move in the focused pane
- `Enter` or `Space`: open the selected target from the knowledge graph pane
- `Esc` or `Backspace`: leave the target inspector view
- `q` or `Ctrl+C`: quit

## Configuration file

Example config:

```json
{
  "target": "http://192.168.1.100",
  "target_domains": [
    "app.example.internal",
    "api.example.internal"
  ],
  "provider": "openai",
  "model": "gpt-4o",
  "base_url": "",
  "max_iters": 50,
  "verbose": false,
  "efficiency_mode": true,
  "ip_whitelist": [
    "192.168.1.100",
    "192.168.1.101"
  ],
  "rules_of_engagement": "Only test systems explicitly authorized by this engagement. Do not perform denial-of-service activity. Stop and report immediately if unintended impact is observed.",
  "credentials": [
    {
      "username": "admin",
      "password": "admin123"
    }
  ]
}
```

Notes:

- CLI flags override config values.
- `max_iterations` is still accepted as a legacy alias for `max_iters` when loading JSON.
- If `ip_whitelist` is empty, discovery is not IP-restricted.

## Runtime outputs

When an engagement runs successfully, Fire Starter writes:

- `fire_starter_report.md`: final markdown report plus a knowledge graph dump
- `fire_starter.db`: SQLite database containing vulnerability records and execution logs

Confirmed module-level proof-of-concept data is carried into vulnerability logging so technical evidence can be retained separately from the final narrative report.

## Architecture at a glance

1. `cmd/fire_starter/main.go` parses flags, loads config, and starts the TUI.
2. `src/agent/workflow.go` initializes the provider, orchestrates targets, and writes the final report.
3. `src/matrix/tool_registry.go` exposes tools from the decision matrix.
4. `src/matrix/real_executor.go` maps techniques to registered module factories in `src/modules/core`.
5. `src/matrix/knowledge_graph.go` aggregates execution results, extracted intelligence, and vulnerability evidence.

## Module development

To add a new built-in technique:

1. Add the technique metadata to `src/matrix/decisions.json`.
2. Implement a module factory in `src/modules/core`.
3. Register it with `RegisterModule(...)` in an `init()` function.
4. Add targeted `_test.go` coverage for the new behavior.

See `docs/building_modules.md` for a fuller developer workflow.

## Testing

Primary verification command:

```bash
go test ./...
```

Useful focused suites:

```bash
go test ./src/agent ./src/matrix ./src/modules/...
```

CI also runs `golangci-lint` with Go `1.26.2`.

## Documentation

- `docs/quick_start.md`: user setup and usage guide
- `docs/test.md`: verification workflow
- `docs/building_modules.md`: module authoring guide
- `docs/agent_data_flow_diagram.md`: orchestration and data flow overview
- `CONTRIBUTING.md`: contribution expectations
- `SECURITY.md`: vulnerability reporting policy

## License

[MIT License](LICENSE)
