# Contributing to Fire Starter

Thanks for contributing.

## Development expectations

- Keep changes aligned with the authorized-security-testing scope of the project.
- Follow existing package structure and naming patterns.
- Add or update tests for behavior changes.
- Ensure `go test ./...` passes before opening a pull request.
- Ensure `golangci-lint` is clean; CI runs it with Go `1.26.2`.

## Repository layout

- `cmd/fire_starter`: CLI entrypoint
- `src/agent`: orchestration, config loading, provider initialization, report generation
- `src/matrix`: decision matrix, tool registry, execution routing, knowledge graph, SQLite persistence
- `src/modules/core`: built-in security testing modules and shared module helpers
- `src/tui`: Bubble Tea terminal interface
- `docs/`: user and developer documentation
- `website/`: static project marketing site

## Adding or changing a module

1. Add or update the technique entry in `src/matrix/decisions.json`.
2. Implement the module in `src/modules/core`.
3. Register it with `RegisterModule(...)` in `init()`.
4. Add a focused `_test.go` file or extend an existing one.
5. Verify the relevant package tests and then run `go test ./...`.

## Documentation changes

If behavior, flags, outputs, or module workflows change, update the matching docs in the same pull request:

- `README.md`
- `docs/quick_start.md`
- `docs/building_modules.md`
- `docs/test.md`
- `website/index.html` when the public project description changes

## Pull requests

Good pull requests include:

- A clear problem statement
- Updated tests when behavior changes
- Updated docs when user-visible or contributor-visible behavior changes
- Small, reviewable commits where possible
