# Quick Start

Fire Starter runs as a terminal-based autonomous security assessment agent. This guide covers the fastest path from clone to first authorized run.

## 1. Prerequisites

- Go `1.26.2` or newer
- Access to an authorized target
- Credentials for the provider you plan to use:
  - `OPENAI_API_KEY`
  - `ANTHROPIC_API_KEY`
  - `GEMINI_API_KEY`
- Or a local OpenAI-compatible endpoint when using `-provider local`

## 2. Build

From the repository root:

```bash
go mod tidy
go build -o fire_starter ./cmd/fire_starter
```

## 3. Run a first engagement

```bash
./fire_starter -target http://127.0.0.1
```

Example with explicit provider settings:

```bash
./fire_starter \
  -target http://127.0.0.1 \
  -provider openai \
  -model gpt-4o \
  -max-iters 10 \
  -verbose
```

Example with a local endpoint:

```bash
./fire_starter \
  -target http://127.0.0.1 \
  -provider local \
  -model llama3.1 \
  -base-url http://127.0.0.1:11434
```

## 4. Use a config file

Create a JSON file and pass it with `-config`:

```json
{
  "target": "http://192.168.1.100",
  "target_domains": ["app.example.internal"],
  "provider": "openai",
  "model": "gpt-4o",
  "base_url": "",
  "max_iters": 25,
  "verbose": false,
  "efficiency_mode": true,
  "ip_whitelist": ["192.168.1.100"],
  "rules_of_engagement": "Only test systems explicitly authorized by this engagement.",
  "credentials": [
    {
      "username": "admin",
      "password": "admin123"
    }
  ]
}
```

Notes:

- CLI flags override config file values.
- `max_iterations` is still accepted as a backward-compatible alias for `max_iters`.
- `efficiency_mode` defaults to `true` unless you explicitly disable it.

## 5. Important flags

- `-target`: target IP or URL
- `-config`: path to JSON config
- `-provider`: `openai`, `anthropic`, `gemini`, or `local`
- `-model`: model identifier
- `-base-url`: provider base URL for local or proxy deployments
- `-max-iters`: maximum control-loop iterations
- `-verbose`: debug logging
- `-efficiency=false`: force deeper target completion rules instead of aggressive triage

## 6. TUI controls

- `Tab`: switch focus between the logs pane and knowledge graph pane
- `Up` / `Down` or `k` / `j`: move in the focused pane
- `Enter` or `Space`: inspect the selected target in the knowledge graph pane
- `Esc` or `Backspace`: exit the inspector view
- `q` or `Ctrl+C`: quit

## 7. What gets written to disk

A completed run produces:

- `fire_starter_report.md`: final markdown report with a knowledge graph dump
- `fire_starter.db`: SQLite database storing execution logs and vulnerability records

## 8. Troubleshooting

- **`go.mod requires go >= 1.26.2`**
  - Upgrade your Go toolchain to 1.26.2 or newer.
- **Unsupported provider**
  - Use one of `openai`, `anthropic`, `gemini`, `local`, or `ollama`-compatible local routing through `local`.
- **Target required errors**
  - Ensure either `-target` or `target` in the config file is set.
- **Unexpected early target completion**
  - Disable default triage behavior with `-efficiency=false`.

## 9. Verify the installation

```bash
go test ./...
```
