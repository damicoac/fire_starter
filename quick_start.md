# Quick Start: Interactive CLI Runloop

This guide explains the interactive runloop in the matrix package so you can quickly understand what it does, how it is structured, and where to extend it.

## Purpose

The runloop is a local simulation harness for decision execution. It is separate from the HTTP server flow and is useful for experimentation while core execution logic is still evolving.

Key files:

- `src/matrix/runloop.go`
- `src/matrix/agent.go`
- `src/matrix/executor.go`

## Architecture at a Glance

`RunLoop` holds four pieces of state (`src/matrix/runloop.go:12-17`):

- `decisions []Decision`: the available matrix options
- `agent Agent`: proposes candidate decisions
- `executor Executor`: executes a chosen decision
- `history []ExecutionResult`: stores prior cycles and outputs

The constructor wires these dependencies together (`src/matrix/runloop.go:19-26`):

- `NewRunLoop(decisions, agent, executor)`

This dependency-injected setup is important because it lets you swap mocks for real components without changing runloop control flow.

## Loop Lifecycle

The interactive control loop is in `Run()` (`src/matrix/runloop.go:87-99`). It repeatedly calls `InteractiveStep()` until the step returns `shouldContinue=false`.

`InteractiveStep()` (`src/matrix/runloop.go:29-84`) does the following each cycle:

1. Prints cycle header.
2. Requests top 3 proposals from the agent:
   - `agent.ProposeDecisions(r.history, r.decisions, 3)` (`src/matrix/runloop.go:33`)
3. Renders the choices to the user.
4. Reads stdin input, validates selected index.
5. Stops loop if user chose `0`.
6. Executes selected technique through executor:
   - `executor.Execute(selected)` (`src/matrix/runloop.go:68`)
7. Appends result to history with timestamp (`src/matrix/runloop.go:77-81`).

## Agent Contract and Mock Behavior

Agent interface (`src/matrix/agent.go:8-11`):

- `ProposeDecisions(history []ExecutionResult, available []Decision, count int) []Decision`

Current mock implementation (`MockAgent`) behavior:

- copies available decisions,
- shuffles randomly,
- returns first `count` entries (`src/matrix/agent.go:30-42`).

Implication: current proposals are random; history is accepted by the interface but not used for ranking yet.

## Executor Contract and Mock Behavior

Executor interface (`src/matrix/executor.go:5-8`):

- `Execute(decision Decision) (string, error)`

Current mock implementation (`MockExecutor`) returns a static success message embedding the selected technique (`src/matrix/executor.go:17-19`).

Implication: no real tool invocation, no stage mapping, no persistence writes.

## Why This Is Useful

This loop gives you a fast environment to test:

- decision proposal UX,
- human approval flow,
- history accumulation,
- future ranking logic and learning behavior.

Because agent and executor are interfaces, you can incrementally replace mock parts with production implementations.

## Practical Extension Path

A common progression:

1. Replace `MockAgent` with a scoring agent that uses `history`.
2. Replace `MockExecutor` with logic that maps `Decision.Technique` to stages and runs real module actions.
3. Persist each cycle outcome (audit/reinforcement) after execution.
4. Add tests for input validation and history-dependent proposal behavior.

## Current Limitation Summary

- Runloop has no dedicated entrypoint in current tree; it is present as a reusable package component.
- Mock components intentionally simulate behavior.
- No built-in automated tests currently target this runloop path.

## File References

- Runloop orchestration: `src/matrix/runloop.go:12-99`
- Agent interface + mock: `src/matrix/agent.go:8-42`
- Executor interface + mock: `src/matrix/executor.go:5-19`
