# E2E Test Refactoring Spec

Status: Proposed
Owner: PMG maintainers
Target branch: `claude/e2e-tests-github-actions-hkxij2`

## Goal

Make PMG's end-to-end (E2E) tests **easy to write, maintain, and extend**, and
let us run them **across Linux, macOS, and Windows** without copy-pasting YAML.
Reliability of PMG is the driver: we expect to add many more E2E cases, so the
cost of adding one must be low and the structure must scale to a 3-OS matrix.

Chosen direction: **Go test harness (testify) for the package-manager matrix +
a shared composite setup action + a reusable sandbox workflow** (Option D from
the analysis). The package-manager matrix must run on **all three OS** in the
near term.

## Current state (what we are replacing)

E2E logic is spread across five places with heavy duplication:

| File | Jobs / content |
|---|---|
| `.github/workflows/pmg-e2e.yml` (808 lines) | One giant `e2e-test` job (~18 inline bash steps) + 3 near-identical sandbox jobs (macOS Seatbelt, Linux Bubblewrap, Linux Landlock) |
| `.github/workflows/action-e2e.yml` | 4 jobs testing the composite `action.yml` |
| `.github/workflows/ci.yml` | `e2e-test` job running `test/e2e.sh` (trivial dry-run smoke) |
| `test/sandbox-e2e.js`, `test/pm-e2e.js` | Node assertions invoked from sandbox jobs |
| `test/e2e.sh` | 3-line dry-run smoke test |
| `sandbox/platform/landlock_e2e_linux_test.go` | Go-based Landlock helper E2E (the pattern we extend) |

### Concrete duplication to eliminate

1. **Environment setup copy-pasted 7+ times.** The
   `checkout → setup-go → corepack → setup-node → pnpm → build → add-to-PATH →
   pmg setup install` block repeats in all 4 jobs of `pmg-e2e.yml`, in
   `action-e2e.yml`, and in `ci.yml`. GitHub Actions has no YAML anchors, so it
   is literal duplication.
2. **The 3 sandbox jobs are ~90% identical.** Same "Create Test
   Directories/Files", same "Disable AppArmor", same 12-line canary-secret
   `env:` block (also duplicated in the `Makefile`), same two run steps. Deltas:
   `runs-on`, driver env var, two extra files on Linux, one Landlock-only step.
3. **Every PM install step has the same shape**
   (`mkdir → init → install A → install B → assert node_modules + manifest →
   rm lockfile → reinstall → re-assert`), hand-written ~10 times for npm, pnpm,
   bun, yarn (proxy/non-proxy) and the pip/pip3/uv/poetry analog.
4. **Hardcoded fixtures repeated everywhere:** `express@5.2.1`/`lodash@4.17.21`,
   `requests==2.32.4`/`numpy==2.3.5`, and malicious markers
   `safedep-test-pkg@0.1.3` / `nyc-config@10.0.0`.
5. **Weak/ad-hoc assertions.** `pmg-e2e.yml:521`
   (`! pmg ... npm install nyc-config@10.0.0 || echo "blocked"`) passes
   regardless of outcome — a real reliability gap. Temp-dir handling is
   inconsistent (`mkdir x && cd x` vs `mktemp -d`).
6. **Multi-OS goal structurally unmet.** The PM matrix is `os: [ubuntu-latest]`
   only; adding an OS today means duplicating a ~500-line job.
7. **No granularity/parallelism.** ~18 PM tests run serially in one 20-minute
   job; one failure masks the rest.

## Target architecture

```
.github/
  actions/
    setup-pmg/action.yml         # composite: toolchains + build pmg + PATH + pmg setup install
  workflows/
    pmg-e2e.yml                  # slim: PM matrix (Go harness) over OS + calls sandbox workflow
    e2e-sandbox.yml              # reusable (workflow_call): sandbox over {os, driver}
    action-e2e.yml               # uses setup-pmg where applicable
    ci.yml                       # e2e-test job replaced by harness smoke (or removed)
test/
  e2e/                           # NEW Go harness (testify, mirrors landlock_e2e pattern)
    main_test.go                 # TestMain: build pmg once, locate repo root
    harness.go                   # RunPmg, project dirs, assert helpers, env seeding
    fixtures.go                  # benign/malicious coordinates, canary env, PM descriptors
    npm_test.go pnpm_test.go bun_test.go yarn_test.go
    pip_test.go uv_test.go poetry_test.go npx_test.go
    modes_test.go                # --dry-run, --silent, --verbose, --debug/--log, --paranoid
    regression_test.go           # httpx NO_PROXY #339, yarn-berry corepack pinning
  sandbox-e2e.js  pm-e2e.js      # kept, still invoked by the sandbox workflow
```

### The Go harness (`test/e2e/`)

Reuse the proven shape from `sandbox/platform/landlock_e2e_linux_test.go`
(walk up to repo root, build/locate `bin/pmg`).

- **Build once:** `TestMain` builds `bin/pmg` a single time per `go test`
  invocation (guarded so a prebuilt binary from `make` is reused in CI).
- **PM descriptor table** drives the repeated pattern instead of bespoke bash:

  ```go
  type packageManager struct {
      name        string   // "npm", "pnpm", "bun", "yarn", ...
      bin         string   // executable to probe on PATH
      initArgs    []string // e.g. {"init", "-y"}
      addArgs     func(pkg string) []string
      installArgs []string // manifest install
      manifest    string   // "package.json" / "pyproject.toml"
      lockfile    string   // "package-lock.json" / "pnpm-lock.yaml" / ...
      proxyModes  []bool   // which proxy modes to exercise
  }
  ```

- **Helpers** (testify `require`/`assert`, per CLAUDE.md):
  - `RunPmg(t, opts, args...) result` — runs `pmg`, captures stdout/stderr/exit.
  - `NewProject(t)` — `t.TempDir()`-based working dir with cleanup for free.
  - `RequireInstalled(t, dir, pkg)`, `RequireManifestContains(t, manifest, pkg)`,
    `RequireLockfile(t, dir, name)`.
  - `RequireBlocked(t, result, marker)` — asserts **non-zero exit AND** the
    "Malicious package blocked" signal AND absence in `node_modules`. This
    replaces every weak `|| echo` block (fixes #5) in one place.
  - `RequireTool(t, name)` — `t.Skip` when a PM is not installed on the runner.
  - `SeedCanaryEnv()` — single source of truth for the scrub/keep canaries
    shared with the sandbox JS scripts and `Makefile`.
- **Fixtures centralized** in `fixtures.go`: benign packages, malicious markers,
  and Python/Node version pins. Changing `express@5.2.1` happens in one place.
- **Granularity & parallelism:** each PM is a table-driven test with subtests
  per `{proxyMode}`; independent cases use `t.Parallel()`.
- **Skips over failures:** tools absent on a given OS (e.g. poetry, bun) are
  skipped via `RequireTool`, not failed — so the same suite is portable.

### Composite setup action (`.github/actions/setup-pmg`)

Encapsulates the repeated environment block with inputs for what each job
needs (`go`, `node`, `pnpm`, `bun`, `python`, `uv`, `poetry`, `build`,
`pmg-setup`). All workflows consume it, killing duplication #1. Pin action SHAs
exactly as today.

### Reusable sandbox workflow (`.github/workflows/e2e-sandbox.yml`)

`on: workflow_call` with inputs `os` and `driver`. Defines the canary `env:`
once, the test-dir/file seeding once, and the AppArmor relaxation + Landlock
probe behind `if:` guards. `pmg-e2e.yml` calls it three times via matrix
(`{macos, seatbelt}`, `{ubuntu, bubblewrap}`, `{ubuntu, landlock}`), collapsing
3 jobs into one definition (fixes #2).

### Slimmed `pmg-e2e.yml`

```yaml
jobs:
  pm-matrix:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: ./.github/actions/setup-pmg
        with: { node: true, pnpm: true, bun: true, python: true, uv: true, poetry: true }
      - run: go test ./test/e2e/... -count=1 -v
  sandbox:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: macos-latest,  driver: seatbelt }
          - { os: ubuntu-latest, driver: bubblewrap }
          - { os: ubuntu-latest, driver: landlock }
    uses: ./.github/workflows/e2e-sandbox.yml
    with: { os: '${{ matrix.os }}', driver: '${{ matrix.driver }}' }
```

Adding a PM = a new descriptor + `_test.go`. Adding an OS = a matrix entry.

## Multi-OS plan (all three soon)

- **Go is the portability lever:** the harness compiles and runs on Linux,
  macOS, and Windows, so the PM matrix fans out via `runs-on` alone.
- **Per-OS tool availability** handled by `RequireTool` skips and by toggling
  setup-action inputs (e.g. don't request poetry where we don't test it).
- **Sandbox is inherently OS-specific** (Seatbelt=macOS, Bubblewrap/Landlock=
  Linux, none on Windows) and stays in the reusable sandbox workflow, not the
  cross-OS PM matrix.
- **Windows risk to resolve in Phase 3 (see Open Questions):** today
  `ci.yml`'s Windows job only runs `./internal/flows/...`, implying limited
  Windows coverage. We must confirm `pmg setup install`, proxy mode, and PATH
  shims behave on Windows before enabling the Windows leg; gate with
  `runtime.GOOS` skips where features are unsupported rather than failing.

## Migration phases

1. **Setup action.** Add `.github/actions/setup-pmg`; switch every existing job
   to it. No behavior change — pure dedupe. Verify CI stays green.
2. **Reusable sandbox workflow.** Extract `e2e-sandbox.yml`; collapse the 3
   sandbox jobs into a matrix. Centralize canaries (workflow + `Makefile` +
   harness reference the same list).
3. **Harness bootstrap.** Stand up `test/e2e/` with the harness, fixtures, and
   **npm + pnpm** ported as proof. Run Linux only. Validate parity with the old
   bash (same packages, same assertions) and fix the `nyc-config` weak check.
4. **Port the rest.** bun, yarn (classic + berry), npx/pnpx, pip, pip3, uv,
   poetry, modes, and the two regression cases (#339, yarn-berry corepack).
   Delete the corresponding inline bash from `pmg-e2e.yml`.
5. **Enable macOS + Windows** legs with `RequireTool`/`runtime.GOOS` skips;
   resolve the Windows support questions; tune the OS-specific toolchain inputs.
6. **Consolidate leftovers.** Fold `action-e2e.yml` block tests and
   `ci.yml`/`test/e2e.sh` smoke into the harness where it reduces surface;
   remove dead scripts.

Each phase is independently shippable and leaves CI green.

## Cross-cutting cleanups (apply during the relevant phase)

- Single source of truth for fixtures and canary env.
- Standardized assertions and `t.TempDir()` lifecycle (no manual `cd`/cleanup).
- `fail-fast: false` + per-PM subtests for at-a-glance failure isolation.
- Fix `pmg-e2e.yml:521` weak malicious-block assertion via `RequireBlocked`.

## Non-goals

- Rewriting the sandbox policy `.js` assertion scripts (kept; only their
  invocation is deduped).
- Changing what PMG itself does; this is test-infrastructure only.
- Eliminating external package-manager processes (PMs are still real
  subprocesses, wrapped by the harness).

## Risks & trade-offs

- **Upfront port cost** is the largest of the options; mitigated by phasing
  (npm/pnpm proof first) and by reusing the existing Landlock E2E pattern.
- **Runner cost:** macOS/Windows minutes are pricier than Linux. Keep
  `fail-fast: false` but consider running the full 3-OS matrix on `main`/nightly
  and a Linux-only fast leg on PRs if minutes become a concern.
- **Windows feature gaps** (above) may force `runtime.GOOS` skips initially;
  acceptable as long as skips are explicit and visible.

## Open questions

1. Does `pmg setup install` + proxy mode + PATH shims work on Windows today? If
   not, which PM cases can run there in Phase 5, and which are skipped?
2. Should the full 3-OS matrix run on every PR, or PR=Linux + nightly/`main`=all
   three to control runner minutes?
3. Keep the sandbox assertions in Node (`test/*.js`) long-term, or eventually
   port them into the Go harness for one language? (Spec assumes: keep Node.)
