# Deep Code Review Notes

## Repository trajectory

The codebase has evolved from a streamable HTTP server concept into a CLI-first autonomous agent architecture. Documentation previously lagged this shift and referenced old run paths.

## Current architecture (validated)

- Entrypoint: `cmd/fire_starter/main.go`
- Agent loop and model/provider integration: `src/agent/workflow.go`
- Decision matrix and tool contract generation: `src/matrix/tool_registry.go`
- Technique dispatch and module execution: `src/matrix/real_executor.go`
- Engagement memory and extraction: `src/matrix/knowledge_graph.go`

## Strengths observed

1. **Solid package-level test coverage**
   - Most matrix/agent/module paths have direct tests.
   - Edge-case tests are present for payload normalization, phase gating, and intelligence extraction.

2. **Clear execution decomposition**
   - `tool_registry` handles naming/schema exposure.
   - `real_executor` handles routing and module invocation.
   - `knowledge_graph` centralizes state and extraction.

3. **Deterministic phase controls**
   - Advancement and submission require explicit evidence and phase coverage.
   - Tool scoring includes anti-repeat pressure via completed-tool penalty.

4. **Resilience in extraction layer**
   - Knowledge graph handles valid JSON and malformed text outputs.
   - Concurrent update behavior is tested.

## Key gaps / risks

1. **Environment mismatch risk**
   - `go.mod` requires `go 1.26.2`; older local toolchains fail quickly.

2. **Documentation drift (fixed in this pass)**
   - Legacy references to `./src/http-server` were outdated.

3. **Large switch-based dispatcher maintenance cost**
   - `src/matrix/real_executor.go` has many technique-specific branches; future growth will increase complexity and merge friction.

4. **Technique naming strictness**
   - Dispatch relies on exact normalized technique strings; matrix changes can silently route to default behavior if not aligned.

## Deferred design note: narrower auth retry path

Current mitigation rate-limits generic `decision_http_request` reopen events caused only by session churn. This keeps cookie or credential changes from repeatedly surfacing the broad HTTP request tool while still allowing one authenticated follow-up for a stable target state.

A better future refinement is to split generic probing from authenticated retry behavior:

- Keep generic `decision_http_request` gated only by target-local intelligence such as phase, open ports, and vulnerabilities.
- Add a narrower authenticated retry path that is allowed only when session state changes and only for the most recently attempted endpoint or helper context.
- Scope that retry path by normalized URL + method + helper finding so auth progression can continue without reopening broad request spam.
- Prefer that narrower path inside vulnerability helpers first, because helpers already operate on a single finding and endpoint family.
