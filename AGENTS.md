# PMG - Development Guide

## Build & Test

```bash
go build ./...          # Build
go test ./... -count=1  # Run all tests
go test ./config/merge/ -v -count=1  # Run specific package tests
go test ./config/merge/ -bench=. -benchmem  # Run benchmarks
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
- Use `testify` (assert/require) for tests
- Table-driven tests preferred
