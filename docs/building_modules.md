# Building Modules

This guide covers how to add a new built-in Fire Starter module.

## Module architecture

Fire Starter loads executable techniques through the module registry in `src/modules/core/registry.go`. The runtime executor in `src/matrix/real_executor.go` looks up a technique by name, builds the module with its factory, executes it, and captures any proof-of-concept evidence recorded through the shared base module.

## Step-by-step workflow

1. Add a technique definition to `src/matrix/decisions.json`.
2. Create a Go implementation in `src/modules/core/`.
3. Register the technique with `RegisterModule(...)`.
4. Accept payload input through helpers such as `PayloadString` and `PayloadInt`.
5. Return structured results from `Execute(ctx)`.
6. Add `_test.go` coverage for the new factory and execution behavior.

## Registry contract

Modules are registered as factories:

```go
type ModuleFactory func(payload map[string]any, onLog func(string)) (ExecutableModule, error)
```

Each module must satisfy:

```go
type ExecutableModule interface {
    Execute(ctx context.Context) (any, error)
    GetUnderlying() any
}
```

Most modules wrap a concrete struct inside `ModuleWrapper`, which gives the executor a uniform interface.

## Recommended implementation pattern

1. Define a module struct that embeds or exposes `BaseModule` behavior when you need shared helpers such as HTTP clients, PoC recording, or cookie injection.
2. Parse payload values in the factory.
3. Return a `ModuleWrapper` whose `ExecuteFunc` calls the concrete implementation.
4. Register the factory from `init()` so it is available at startup.

Example shape:

```go
package core

import "context"

type MyModule struct {
    BaseModule
    Target string
}

func (m *MyModule) Execute(ctx context.Context) (any, error) {
    return map[string]any{
        "status": "ok",
        "target": m.Target,
    }, nil
}

func init() {
    RegisterModule("my_module", func(payload map[string]any, onLog func(string)) (ExecutableModule, error) {
        target := PayloadString(payload, "url", "http://127.0.0.1")
        module := &MyModule{Target: target}
        return ModuleWrapper{
            Module: module,
            ExecuteFunc: func(ctx context.Context) (any, error) {
                return module.Execute(ctx)
            },
        }, nil
    })
}
```

## Proof-of-concept evidence

If a module confirms a finding, record technical evidence through the base module so the executor can include it in `reproduction_steps`:

```go
m.RecordPoC(req, bodyBytes, "Finding description")
```

The knowledge graph and vulnerability logging pipeline can then promote that evidence into database-backed findings.

## Testing guidance

At minimum, cover:

- Factory construction with representative payloads
- Successful execution path
- Failure path for malformed targets or invalid inputs
- PoC capture behavior when the module records a finding

Run:

```bash
go test ./src/modules/...
go test ./...
```

## Design notes

- Keep modules focused on one technique.
- Prefer structured result objects over large free-form strings.
- Reuse shared helpers from `BaseModule` and `registry.go` instead of re-implementing parsing logic.
- Do not add modules under `src/modules/community/` unless the runtime is updated to load them; the current executor imports factories from `src/modules/core`.
