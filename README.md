# Blackwater Streamable Matrix Server

This project provides a streamable HTTP server that exposes decision-matrix techniques as callable tools and executes the mapped module flow.

## Build

From the repository root:

```bash
go mod tidy
go build -o blackwater-server ./src/http-server
```

Run the built binary:

```bash
./blackwater-server
```

## Run Without Building

```bash
go run ./src/http-server
```

Server listens on `http://localhost:8080`.

## API Endpoints

- `GET /tools` → returns all exposed tools derived from `src/matrix/decisions.json`
- `POST /execute` → executes by `identifier` or `tool_name` and streams NDJSON updates

## Quick Test Commands

List tools:

```bash
curl -s http://localhost:8080/tools | jq
```

Execute by decision identifier:

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

More live test examples are documented in `test.md`.

## Development Notes

When adding a new decision in `src/matrix/decisions.json`, ensure its technique is mapped in `src/matrix/real_executor.go` (`MapTechniqueToStage`) so execution routes to the correct module stage.
