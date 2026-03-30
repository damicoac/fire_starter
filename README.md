# Blackwater Streamable Matrix Server

This directory contains a custom standalone Streamable HTTP Server (`cmd/http-server`) designed to bridge LLM agents with the `fire_starter` framework natively.

Instead of utilizing standard MCP (stdio or SSE), this server opts for raw HTTP POST streaming utilizing chunked responses and **NDJSON** (Newline Delimited JSON). This allows an associated AI agent to observe real-time module execution and automatically retrieve the decision matrix once execution is finalized.

## Architecture

- `cmd/http-server/main.go`
  - Long-lived Go HTTP server (`:8080`) that streams updates block-by-block.
  - Bundles the execution logs natively alongside the completion Matrix tree to minimize agent roundtrips.
- `fire_starter/matrix/real_executor.go`
  - Represents the real translation layer between `Decisions.json` logic strings (e.g., `port_scanning`) and actual `fire_starter.Tree` executable stages (e.g., `api-testing.recon`).
- `fire_starter/matrix/decisions.json`
  - Stored file holding all available autonomous tool decisions provided to the agent for execution.

---

## How to Run

Because the HTTP server relies on parsing the `decisions.json` file inside the `matrix` package tree, run this from the root of your project:

```bash
# From the fire_starter- root directory:
go run ./cmd/http-server
```

*(The server will start processing on `http://localhost:8080/execute`)*

## How to Test and Interact

Use a client that supports unbuffered HTTP stream reading (like `curl -N`) to observe real-time tool/module executions. 

```bash
curl -N -X POST http://localhost:8080/execute \
     -H 'Content-Type: application/json' \
     -d '{"identifier":"0000", "payload":{"ip":"192.168.1.100"}}'
```

### Stream Pipeline:
The stream emits logs sequentially as NDJSON lines. 
1. Log Levels (`info`, `debug`, `error`) are streamed as the action runs.
2. When completed, the `Done: true` signal is emitted containing your final `Result` strings and the full `Matrix` for your agent's context window.

---

## How to Develop for This

When extending the decision tree or the AI agent logic, you must carefully map new tool techniques so the Server knows how to trigger the underlying codebase.

### 1. Adding a new Tool to the Agent
Edit `fire_starter/matrix/decisions.json` and append a new `Decision` struct.
```json
{
  "use_case": "Harvesting specific internal logs",
  "technique": "log_extraction",
  "function": "target specific web servers log paths",
  "identifier": "0040"
}
```

### 2. Wiring Execution Mapping
Open `fire_starter/matrix/real_executor.go`.
Scroll to the `MapTechniqueToStage()` switch statement.
You must update the string matching logic to map your new `technique` to a valid internal `Stage` constant used by the `fire_starter` library.

```go
case strings.Contains(t, "log_extraction"):
    return "application-mapping.explore" // Example fallback stage!
```
If you do not map your new `technique`, the executor will gracefully default to `application-mapping.explore` under the assumption that an unrecognized technique is informational mapping.

### 3. Payload Requirements 
The `execute` POST allows the agent to provide unstructured inputs into `{"payload": { ... }}`. 
In `fire_starter/matrix/real_executor.go` within `ExecuteReal()`, we ensure that standard required parameters such as `ip` and `url` populate successfully. If your new nodes strictly require new context variables (like `{"bucketName": "test-12"}`), verify your AI agent is capable of providing it through the `POST` interface payload schema.
