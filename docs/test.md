# Live API Test Commands

## 1) Start the server

```bash
go run ./src/http-server
```

## 2) List exposed tools

```bash
curl -s http://localhost:8080/tools | jq
```

## 3) Execute by decision identifier

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"0000","payload":{"ip":"192.168.1.100","url":"http://192.168.1.100"}}'
```

## 4) Execute by tool name

Get exact tool names from `/tools` first.

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"decision_port_scanning","payload":{"target":"192.168.1.100"}}'
```

## 5) Negative test: missing selector

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"payload":{"target":"192.168.1.100"}}'
```

## 6) Negative test: unknown identifier

```bash
curl -N -X POST http://localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"9999"}'
```
