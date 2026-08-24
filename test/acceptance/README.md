# PMG Acceptance Suite

The suite runs the real `pmg` binary through user-facing commands and checks that PMG keeps its
promises. It runs against production: a live malysis backend and real package registries. It is not
hermetic.

The suite runs three ways: on manual dispatch, on a nightly schedule, and as an advisory check on
pull requests that change code. The pull-request check does not block a merge. Keep it out of the
required checks, so a stale fixture or a backend outage never blocks an unrelated pull request.

`test/proxye2e` stays separate. `proxye2e` runs in process and owns proxy-flow correctness. This
suite owns the real-binary guarantees. The two do not overlap.

## Files

```
test/acceptance/
  catalog.yaml          # guarantee inventory: id, category, tier, guarantee, labels
  catalog.go            # catalog schema, loader, id derivation, selector
  integrity_test.go     # TestCatalogIntegrity — guards catalog/script drift (runs in normal CI)
  acceptance_test.go    # TestAcceptance — real-binary harness (//go:build acceptance)
  report/               # joins JUnit results with the catalog into a Markdown report
  scripts/
    <category>/<capability>/<name>.txtar
```

## Feature id

A script's feature id is its path under `scripts/`, without `.txtar`, with `/` kept:

```
scripts/npm/guard/malware-block.txtar   ->   npm/guard/malware-block
```

A hyphen inside a segment stays literal. The subtest name, `TestCatalogIntegrity`, and the report
all use this rule to agree on identity. Put every script at least two levels deep:
`<category>/.../<name>.txtar`.

## Add a case

1. Add a script at `scripts/<category>/.../<name>.txtar`.
2. Add a row to `catalog.yaml`:

   ```yaml
   - id: <category>/.../<name>
     title: "short title"
     category: <category>
     tier: P0                 # P0 | P1 | P2
     guarantee: "what must hold"
     labels: [malware, block] # optional
   ```

That is the whole change: one script, one catalog row. No scaffolding, no per-case Go code.

`TestCatalogIntegrity` runs under normal `go test ./...`. It fails when a script has no catalog row,
so a typo cannot become a guarantee. A catalog row with no script is a gap: the report shows it, and
it never fails the build.

## Write a script

Scripts are [`testscript`](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript) txtar
files. The harness puts `pmg` on `$PATH`, so `exec pmg ...` runs the built binary.

`testscript` sets `HOME=/no-home`, which is not writable. Set a writable `HOME` first in any script
that runs a package manager or `pmg setup install`:

```
env HOME=$WORK/home
mkdir $WORK/home
```

The suite hits production, so assert stable, coarse guarantees only: a known-malicious package is
blocked, a clean install succeeds, shims are created. Do not assert a value that the live service
returns by chance, such as a specific suspicious verdict or a cooldown window. That belongs in
`test/proxye2e`.

### Malware-block cases

Do not use `--dry-run`. It skips analysis and always exits zero, so it cannot prove a block. A
non-zero exit alone is also weak, because a package manager can fail for other reasons. Assert PMG's
block line on stdout and the missing package:

```
! exec pmg npm --no-cache --prefer-online install safedep-test-pkg@0.1.3
stdout 'Malicious package blocked'
! exists node_modules/safedep-test-pkg
```

Keep the known-malicious fixture malicious, or the test means nothing. SafeDep flags
`safedep-test-pkg` on both registries: use `safedep-test-pkg@0.1.3` on npm and `safedep-test-pkg==0.0.4`
on PyPI.

### Cloud-mode cases

A case that needs SafeDep Cloud credentials guards on the `cloud` condition and skips when no
credentials are present (a fork, a local run):

```
[!cloud] skip 'no cloud credentials'
```

Credentials reach only the `cloud` category. `testscript` does not forward host environment, so the
harness forwards `SAFEDEP_API_KEY`, `SAFEDEP_TENANT_ID`, and `PMG_CLOUD_ENABLED` into a script only
when its first path segment is `cloud`. The community-category scripts always use the unauthenticated
`community-api.safedep.io` path; only `cloud/...` scripts use the authenticated `api.safedep.io`
path. Put an authenticated-path guarantee under `scripts/cloud/`.

## Category and labels

Every guarantee has a `category` (the first path segment) and optional `labels`. A run filters on
both:

- `ACCEPTANCE_CATEGORY=npm` runs the scripts in one category.
- `ACCEPTANCE_LABELS=malware,clean` runs the scripts that carry any of those labels.
- Set both to narrow further: a script runs when its category matches **and** it carries one of the
  labels.

The workflow takes `category` and `labels` as dispatch inputs and passes them to the harness as
environment variables, never as shell arguments.

## Run it

```bash
# Catalog integrity only (fast, offline, part of normal CI):
go test ./test/acceptance/ -run TestCatalogIntegrity

# Full suite against prod (needs network and the package managers your scripts use):
go test -tags acceptance ./test/acceptance/

# Reuse a prebuilt binary:
PMG_BIN=$PWD/bin/pmg go test -tags acceptance ./test/acceptance/

# Filter by category or labels:
ACCEPTANCE_CATEGORY=npm go test -tags acceptance ./test/acceptance/
ACCEPTANCE_LABELS=malware go test -tags acceptance ./test/acceptance/

# Render the report from a JUnit file:
gotestsum --junitfile acceptance.xml -- -tags acceptance ./test/acceptance
go run ./test/acceptance/report -junit acceptance.xml -catalog test/acceptance/catalog.yaml -scripts test/acceptance/scripts
```

The report groups guarantees by category, then tier: pass, fail, skip, unknown, gap. It shows the
guarantee text and, for a failure, the captured line. It exits zero for normal results. A missing or
broken JUnit file is an error, not zero coverage.
