# PMG - Development Guide

## Build & Test

```bash
go build ./...          # Build
go test ./... -count=1  # Run all tests
go test ./config/ -v -count=1  # Run specific package tests
```

## Project Structure

- `cmd/` — CLI commands (npm, pypi, setup, version)
- `config/` — Configuration loading, templates, merging
- `sandbox/` — Sandbox policy enforcement (macOS Seatbelt, Linux Bubblewrap)
- `proxy/` — Proxy-based package interception
- `guard/` — Guard-based package analysis
- `analyzer/` — Package security analysis
- `internal/` — Internal utilities (analytics, eventlog, flows, ui)

## Code Style

- Keep things short and simple
- Avoid unnecessary code comments
- Use comments for trade-offs, known uncovered cases, and anything useful for a human reader
- Code itself should be readable without comments explaining the obvious
- Follow existing patterns in the codebase
- Use `testify` (assert/require) for test assertions — do not use raw `if` checks with `t.Errorf`/`t.Fatalf`
- Use `require` for assertions that should stop the test on failure (e.g. nil error checks before using a value)
- Use `assert` for assertions where the test can continue after failure
- Table-driven tests preferred

## Code Reuse

- Follow DRY — do not duplicate code
- Prefer refactoring existing code for reusability over copying and modifying
- Extract shared logic into functions or packages when patterns repeat

## Error Handling

- Never swallow errors — always handle them explicitly
- Prefer failing fast by returning errors up the call stack
- When soft failure is acceptable, log with `log.Warnf` from `github.com/safedep/dry/log`
- Do not use `_ = someFunc()` to discard errors silently
