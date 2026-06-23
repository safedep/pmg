# PMG - Development Guide

**DO NOT USE UNNECESSARY CODE COMMENTS** - The code is read and written by humans who are proficient
in Go programming language. Write idiomatic Go code following DRY and SOLID principles. DO NOT SHY
AWAY FROM PROPOSING REFACTORING THAT IMPROVES THE CODE BASE.

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

## Proxy E2E Tests

- `test/proxye2e/` is a hermetic (no network) table-driven framework for the proxy flow. It
  runs the real proxy, interceptors, cooldown handlers and analyzer verdict-mapping against an
  in-process mock registry and a stub malysis gRPC client.
- Any security-sensitive change to the proxy flow (interceptors, cooldown, malware
  allow/confirm/block, trusted/insecure bypass, new controls) MUST add or extend an E2E case
  in `test/proxye2e/`. Add a `TestCase` with `Config`/`Setup`/`Exec`/`Assert`; do not build new
  scaffolding.

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
- For CLI/user-facing errors, prefer `usefulerror` with a specific code and actionable help so `ui.ErrorExit` does not classify expected failures as `Unknown`
- Check the error from `fmt.Fprintf`/`fmt.Fprintln`/`fmt.Fprint` (the `errcheck` linter flags these). Return it up the stack: `if _, err := fmt.Fprintf(out, ...); err != nil { return err }`
