# PMG Acceptance Suite

This suite drives the **real `pmg` binary** through user-facing CLI flows and asserts PMG's
guarantees end to end. It runs against **production** (a live malysis backend and real package
registries), so it is non-hermetic by design and runs on manual dispatch and a nightly schedule,
not on every PR.

It is separate from and does not overlap with `test/proxye2e`. `proxye2e` stays hermetic and
in-process and owns proxy-flow correctness; this suite owns real-binary guarantees.

## Layout

```
test/acceptance/
  catalog.yaml          # guarantee inventory: id, surface, tier, guarantee text
  catalog.go            # catalog schema, loader, id derivation
  integrity_test.go     # TestCatalogIntegrity — guards catalog/script drift (runs in normal CI)
  acceptance_test.go    # TestAcceptance — real-binary harness (//go:build acceptance)
  report/               # JUnit ⋈ catalog → per-surface/tier Markdown report
  scripts/
    <surface>/<capability>/<name>.txtar
```

## Feature id: derived from the path

A script's **feature id** is its path under `scripts/`, with `.txtar` removed and `/` kept:

```
scripts/npm/guard/malware-block.txtar   →   npm/guard/malware-block
```

Hyphens inside a segment are literal; they never split into path. This one rule is what the
subtest name, `TestCatalogIntegrity`, and the report mapper all use to agree on identity. Scripts
live at least two levels deep (`<surface>/.../<name>.txtar`).

## Adding a case

1. Add a script at `scripts/<surface>/.../<name>.txtar`.
2. Add a matching row to `catalog.yaml` with a `tier` (`P0` | `P1` | `P2`):

   ```yaml
   - id: <surface>/.../<name>
     title: "short human title"
     surface: <surface>
     tier: P0
     guarantee: "what must hold, stated as a promise"
   ```

That is the whole change: one script, one catalog row. No scaffolding, no per-case Go code.

`TestCatalogIntegrity` runs under normal `go test ./...`. It fails if a script has no catalog
entry (a typo or an un-cataloged script cannot become a phantom guarantee). A catalog entry with
no script yet is an allowed **gap**: reported, never a failure.

## Writing a script

Scripts are [`testscript`](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript) `txtar`
files. The harness puts `pmg` on `$PATH`, so `exec pmg ...` runs the built binary.

`testscript` sets `HOME=/no-home` (deliberately not writable). Any case that runs a package
manager or `pmg setup install` must set a writable `HOME` first:

```
env HOME=$WORK/home
mkdir $WORK/home
```

Because the suite hits real prod, assert **stable, coarse** guarantees only — "known-malicious is
blocked", "a clean install succeeds", "shims are created". Do not assert values the live service
returns unpredictably (a specific suspicious verdict, a cooldown window); that deterministic
mapping belongs in `test/proxye2e`.

### Malware-block cases

Do **not** use `--dry-run`: it skips analysis and always exits zero, so it cannot prove a block. A
non-zero exit alone is also not enough (a package manager can fail for unrelated reasons), so
assert PMG's block signal on stdout and the package absence:

```
! exec pmg npm --no-cache --prefer-online install safedep-test-pkg@0.1.3
stdout 'Malicious package blocked'
! exists node_modules/safedep-test-pkg
```

Known-malicious fixtures (must stay malicious for the tests to mean anything): `safedep-test-pkg`
(npm) and `nyc-config@10.0.0`.

### Cloud-mode cases

Cases that need SafeDep Cloud credentials guard on the `cloud` condition and skip visibly when no
credentials are present (forks, local runs), so a credential-less run stays honest instead of red:

```
[!cloud] skip 'no cloud credentials'
```

The harness reports `cloud` true when credentials resolve from the keychain or the
`SAFEDEP_API_KEY` / `SAFEDEP_TENANT_ID` environment.

## Running locally

```bash
# Catalog integrity only (fast, no network, part of normal CI):
go test ./test/acceptance/ -run TestCatalogIntegrity

# Full real-binary suite against prod (needs network + the package managers your scripts use):
go test -tags acceptance ./test/acceptance/

# Reuse a prebuilt binary instead of building main.go:
PMG_BIN=$PWD/bin/pmg go test -tags acceptance ./test/acceptance/

# Render the report from a JUnit file:
gotestsum --junitfile acceptance.xml -- -tags acceptance ./test/acceptance
go run ./test/acceptance/report -junit acceptance.xml -catalog test/acceptance/catalog.yaml
```

The report groups guarantees by surface then tier: ✅ pass · ❌ fail · ⏭️ skip · ⚪ gap, with the
guarantee text and, for failures, the captured detail. In Part 1 it always exits 0 — visibility,
not enforcement.
