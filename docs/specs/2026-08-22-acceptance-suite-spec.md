# Acceptance Suite Spec

- Date: 2026-08-22
- Status: Implemented (Part 1)
- Topic: `acceptance-suite`

## Problem

PMG ships fast, increasingly with AI coding agents authoring the changes. The test coverage
is already deep — ~180 unit test files, the hermetic `test/proxye2e` framework, and several
real-binary E2E workflows (`pmg-e2e.yml`, sandbox/action/persistent-proxy). But there is no
single answer to the two questions a release actually turns on:

1. **What are the important features PMG promises, and does each still work?** The intent is
   scattered across `AGENTS.md`, spec docs, and several CI YAMLs. No one place enumerates the
   guarantees, and nothing reports, per guarantee, "proven / broken / not covered yet."
2. **Is this build safe to ship?** Pushing a `v*` tag triggers `goreleaser` build+publish
   directly. The tag workflow does not depend on the test suites.

This spec covers **Part 1 only**: build the acceptance suite with reporting and visibility,
authorable by humans and agents, invoked via manual workflow dispatch, **non-gating**. Part 2
(making it a release gate) is described but out of scope until the suite is reliable and
maintainers have bought in.

## Goals

- A from-scratch **acceptance suite** under `test/acceptance/` that drives the **real `pmg`
  binary** through user-facing CLI flows and asserts PMG's guarantees end to end.
- A **guarantee catalog** covering the full user-facing surface, that reports each guarantee as
  proven, broken, or **not yet covered** — full-surface visibility from day one.
- **Trivial authoring for humans and agents**: adding a case is adding one declarative script
  file; adding a guarantee is one catalog entry. No new scaffolding, no bespoke runner.
- **Reporting and visibility**: a per-surface, per-tier report of results plus coverage gaps,
  published to the GitHub Actions job summary and uploaded as an artifact.
- **Manual invocation** via `workflow_dispatch` plus a nightly `schedule`.
- A `tier` on every guarantee (P0/P1/P2) recorded now, wired to nothing yet, so the Part 2 gate
  policy is already encoded and reviewed before it has teeth.

## Non-goals

- **Not a release gate in Part 1.** The suite reports; it never blocks a tag or publish.
- **Not a replacement for, or overlap with, `test/proxye2e`.** `proxye2e` stays hermetic,
  in-process, stubbed backend, fast, part of `go test ./...` and PR CI. It owns proxy-flow
  correctness. The acceptance suite owns real-binary guarantees.
- **Not a new test-execution framework.** Execution is `testscript` + `go test`; reporting is
  `gotestsum` + JUnit. The only code authored is the catalog and a thin mapper.
- **Not hermetic.** Running the real binary means real dependencies (a live malysis backend,
  real registries, stable known-malicious fixtures). This is intentional. It is why the suite
  is dispatch/nightly, not per-PR.

## Approach

### Division of labor

| Layer | Real binary? | Backend | Runs | Owns |
|---|---|---|---|---|
| `go test ./...` (unit) | no | n/a | PR CI | package-level logic |
| `test/proxye2e` | no (in-process stack) | stubbed gRPC | PR CI | proxy-flow correctness |
| `test/acceptance` | **yes** | **live malysis + real registries** | **manual / nightly** | user-facing guarantees end to end |

### Tooling

- **`testscript`** — declarative `txtar` scripts: run a command, assert stdout/stderr/exit code,
  assert files.
- **`gotestsum`** — runs `go test` over the suite and emits JUnit XML.
- **`catalog.yaml` + a mapper** — the only custom code. `gotestsum` reports pass/fail for cases
  that *exist*; it cannot report guarantees that have *no* case. That gap inventory is the
  full-surface visibility requirement.

### Feature-id derivation (load-bearing)

A script's feature id is its path under `scripts/`, `.txtar` removed, `/` kept:
`scripts/npm/guard/malware-block.txtar` → `npm/guard/malware-block`. Hyphens inside a segment are
literal. The subtest name, `TestCatalogIntegrity`, and the report mapper all use this one rule to
agree on identity.

### The guarantee catalog

`test/acceptance/catalog.yaml` is the source of truth for "what must work". IDs are hierarchical
and greppable (`<surface>/<capability>/<specific>`). Coverage is derived, not authored: a
guarantee is covered if a script whose feature id equals its id exists, else it is a gap. `tier`
is recorded but inert in Part 1.

### Reporting and visibility

The workflow runs `gotestsum --junitfile acceptance.xml -- -tags acceptance ./test/acceptance`.
The mapper (`report/`) joins the JUnit results with `catalog.yaml` by feature id and renders
Markdown grouped by surface then tier: ✅ pass · ❌ fail · ⏭️ skip · ⚪ gap, with rollups per tier
and a P0-coverage count. The report is written to `$GITHUB_STEP_SUMMARY` and uploaded as an
artifact. The mapper exits 0 in Part 1 — visibility, not enforcement.

### Manual workflow

`.github/workflows/acceptance.yml` triggers on `workflow_dispatch` (inputs: `ref`, optional
`surface` filter) and a nightly `schedule`. It builds `pmg`, runs the suite, publishes the
summary, and uploads the artifact. Non-gating: no other workflow depends on it.

### Real-binary dependencies and fixtures

- **Backend**: real prod, in both analyzer modes. Community mode (no credentials) →
  `community-api.safedep.io`, unauthenticated. Cloud mode (SafeDep Cloud creds) → authenticated
  analyzer against `api.safedep.io`. Cloud-mode cases skip with a visible status when secrets are
  absent.
- **Known-malicious fixtures**: `nyc-config@10.0.0` and `safedep-test-pkg` are the anchors. A
  fixture going stale is a cataloged, fixable event.
- **Determinism caveat**: guarantees that depend on values the live service returns
  unpredictably are not acceptance-suite material; their deterministic mapping stays in
  `proxye2e`.

## Implementation notes (Part 1)

- The real-binary `TestAcceptance` is behind `//go:build acceptance` so `go test ./...` (PR CI)
  never runs it. `TestCatalogIntegrity` and the report tool carry no build tag and run in normal
  CI.
- `--dry-run` is **not** used in malware-block cases: it skips analysis and always exits zero, so
  it cannot prove a block. Cases assert PMG's stdout block signal (`Malicious package blocked`)
  and the package absence, mirroring the proven `pmg-e2e.yml` invocations.
- `pip/guard/malware-block` ships as a cataloged **gap**: the repo has no proven malicious PyPI
  fixture yet (`safedep-test-pkg` is an npm package). Clean-allow pip coverage is a real install.

## Part 2 (future — described, not built)

Once the suite is green-reliable and maintainers agree: promote acceptance to a required check
and/or add an acceptance-gate job that `goreleaser.yml` `needs:`. The `tier` field decides
behavior per guarantee: P0 failure blocks the release, P1 blocks but is overridable, P2 warns.
No catalog or case rewrite is required — only the gate wiring and the mapper's exit policy change.
