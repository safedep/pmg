# Spec: Environment Variable Protection (Process-Level Env Scrubbing)

Status: Draft
Owner: PMG sandbox
Related: `sandbox/util/dangerous.go` (`DANGEROUS_FILES`), `docs/sandbox.md`

## 1. Background

Modern software supply chain worms increasingly steal credentials from the
**process environment** rather than from files on disk. The SafeDep analysis of
the Miasma / Mini Shai-Hulud toolkit
(<https://safedep.io/inside-the-miasma-supply-chain-attack-toolkit>) documents
this directly:

- The payload is **TypeScript executed via Bun**, with a build-time
  *"Env-scramble"* transform that rewrites `process.env.GITHUB_TOKEN` into
  `process.env[scramble("GITHUB_TOKEN")]`, hiding the variable **names** from
  static analysis. It skips only `NODE_ENV` and `TZ`.
- A `Provider` abstraction harvests source-specific credentials from
  **AWS, Azure, GCP, Kubernetes, HashiCorp Vault, and password managers
  (1Password, Bitwarden)**, then a `Collector` + `Sender` chain exfiltrates them.
- Persistence drops a **Python** hourly C2 agent (`GITHUB_MONITOR.py`).
- Exfiltration rides **GitHub commit search / commits over `github.com:443`** —
  the same host PMG's npm profile already allowlists — so **network egress
  filtering cannot stop this exfil**. The only control that breaks the kill
  chain is *preventing the read* in the first place.

When a developer runs `pmg npm install` (or `pip`, `uv`, etc.), any malicious
install hook or transitive dependency inherits PMG's full environment, including
`AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, `TWINE_PASSWORD`, and similar. PMG already
blocks credential **files** by default (`DANGEROUS_FILES`); this spec extends the
same default-deny philosophy to **environment variables**.

## 2. Goals and non-goals

### Goals

- Scrub a default-deny list of sensitive environment variables from the child
  process environment before a package manager command is executed.
- Make the deny list **configurable**, mirroring `DANGEROUS_FILES`: a built-in
  default that profiles can extend and selectively override.
- Let each sandbox **profile re-allow ecosystem-specific variables** so package
  managers keep working without surprise friction (e.g. npm keeps `NPM_TOKEN`).
- Work on **all platforms**, since it is plain environment filtering and does
  not depend on OS sandbox primitives (Seatbelt / Bubblewrap / Landlock).

### Non-goals (accepted risk for v1)

- **We accept that a malicious payload run by a given ecosystem can steal that
  ecosystem's own publishing token.** A malicious JS package executed during
  `npm install` can still read `NPM_TOKEN` (the npm profile re-allows it), but
  **not** a PyPI token or an AWS key. Symmetrically, a malicious Python package
  cannot read `NPM_TOKEN` or `AWS_*`. This is a deliberate trade-off: the
  ecosystem's own auth token must be present for the package manager to
  function, and removing it would break legitimate publish/auth flows.
- We do **not** attempt to defeat secrets read via other channels (process
  memory, `/proc`, files). Those are listed under Future Enhancements.
- We do **not** introduce a full default-deny-all (allowlist-only) environment
  in v1. That is a future, higher-friction mode (see §9).

## 3. Design overview

Two layers, exactly mirroring the `DANGEROUS_FILES` model:

1. **Built-in default deny list** — `DANGEROUS_ENV_VARS` in `sandbox/util`,
   an explicit, curated list of **known** credential variable names (e.g.
   `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `TWINE_PASSWORD`). No generic
   `*_TOKEN` / `*_SECRET` catch-alls live in the default — they would clip
   legitimate build variables for every user. The list is a precise enumeration
   that grows one literal name at a time.

2. **Per-profile `environment:` section** — each sandbox policy may declare
   additional `deny` patterns and `allow` patterns. The **matching engine
   supports glob wildcards**, so a profile that wants aggressive coverage can
   opt into it explicitly (e.g. `deny: ["*_TOKEN", "AWS_*"]`) without that risk
   being imposed on everyone by default. `allow` suppresses matching built-in or
   profile denies (allow always wins), letting each ecosystem re-permit the
   variables its package manager legitimately needs.

Enforcement is a single chokepoint: in `executor.ApplySandbox`, after the
sandbox policy is resolved **and after the project overlay and runtime
`--sandbox-allow` overrides have been merged into it**, the resolved environment
policy is applied to `cmd.Env`, removing denied variables before the child
process is spawned. `ApplySandbox` is already the shared entry point for both
the guard and proxy flows and runs before the direct and PTY launch paths, so
one integration point covers every package-manager child PMG spawns — and it
sits downstream of overlays and CLI overrides, so those compose for free.

```
os.Environ()
  -> shim.FilterPMGFromEnv()        (existing: strips PMG_SHIM_PATH, ~/.pmg/bin)
  -> mergeEnv(overrides)            (existing)
  -> [cmd.Env set in runner]
  -> executor.ApplySandbox():
        resolve policy                                   (includes environment:)
        applyProjectOverlay(policy, ...)                 (existing; now also env allow)
        applyRuntimeOverrides(policy, --sandbox-allow)   (existing; now also env allow)
        cmd.Env = util.ScrubEnv(cmd.Env, policy.Environment)   <-- NEW, last step
        apply OS sandbox
  -> exec child (direct / PTY / proxy)
```

### Why enforcement is gated on sandbox being enabled

To stay consistent with `DANGEROUS_FILES` (which only takes effect when the
sandbox is enabled) and to honor "can be overridden by sandbox config," v1
enforces env scrubbing **only when the sandbox is enabled for the package
manager**. If a profile is explicitly disabled for a PM, no scrubbing occurs —
disabling the sandbox disables all of its protections, which is the existing,
predictable contract. Making env scrubbing always-on regardless of sandbox
state is called out as a future enhancement (§9) because it is independently
valuable (it needs no OS sandbox support) but changes the current contract.

## 4. Configuration schema

### 4.1 Policy YAML (`sandbox/profiles/*.yml`)

A new optional top-level `environment:` block on `SandboxPolicy`:

```yaml
environment:
  # Extra variable-name patterns to scrub, in addition to the built-in
  # DANGEROUS_ENV_VARS default deny list. Case-insensitive globs are supported,
  # so a profile can opt into broad matching that the default list omits.
  deny:
    - MY_CUSTOM_SECRET
    - "*_TOKEN"        # opt-in wildcard: not in the built-in default
    - "AWS_*"

  # Variable-name patterns to keep even if a built-in or profile deny would
  # otherwise scrub them. Allow always wins. Case-insensitive globs.
  allow:
    - NPM_TOKEN
    - NODE_AUTH_TOKEN
    - npm_config_*
```

Go types (in `sandbox/policy.go`):

```go
type SandboxPolicy struct {
    // ... existing fields ...
    Environment EnvironmentPolicy `yaml:"environment" json:"environment"`
}

// EnvironmentPolicy controls which environment variables are scrubbed from
// the child process. Deny extends the built-in DANGEROUS_ENV_VARS; Allow
// suppresses matching denies (allow wins). Patterns are case-insensitive
// name globs.
type EnvironmentPolicy struct {
    Allow []string `yaml:"allow" json:"allow"`
    Deny  []string `yaml:"deny"  json:"deny"`
}
```

Inheritance: `Environment.Allow` and `Environment.Deny` are unioned with the
parent in `MergeWithParent` (same semantics as filesystem/network/process
lists). No path expansion is needed in `ResolveProfile` (these are variable
names, not paths), but the slices are deep-copied like the others.

### 4.2 `config.template.yml`

Document the new section under the sandbox docs block, including the note about
the accepted-risk trade-off and a pointer to this spec. No new top-level config
key is required — env protection is part of the per-PM sandbox policy.

## 5. Built-in default deny list (`DANGEROUS_ENV_VARS`)

Lives next to `DANGEROUS_FILES` in `sandbox/util/dangerous.go`.

**The built-in list contains only explicit, known secret-bearing variable
names — no generic `*_TOKEN` / `*_SECRET` style catch-alls.** Generic wildcards
in the default list carry too much risk of silently clipping a legitimate build
variable, and the false-positive blast radius would land on every user. We
prefer a precise, auditable enumeration that we curate as new credential
variables become known.

Wildcards are intentionally **not** in the default list, but the **matching
engine fully supports glob patterns** (see §7). Users who want broader, more
aggressive coverage opt into it explicitly per profile via
`environment.deny` (e.g. add `"*_TOKEN"` or `"AWS_*"` to a profile). This keeps
the default safe and predictable while leaving aggressive matching one config
line away for those who want it.

Indicative starting set (curated; finalized in implementation review):

```go
var DANGEROUS_ENV_VARS = []string{
    // Cloud providers
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
    "ARM_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "DIGITALOCEAN_ACCESS_TOKEN",

    // Package registry / publishing tokens
    "NPM_TOKEN", "NPM_AUTH_TOKEN", "NODE_AUTH_TOKEN", "NPM_CONFIG__AUTH",
    "TWINE_USERNAME", "TWINE_PASSWORD",
    "PYPI_TOKEN", "UV_PUBLISH_TOKEN", "FLIT_PASSWORD",
    "POETRY_PYPI_TOKEN_PYPI", "POETRY_HTTP_BASIC_PYPI_PASSWORD",
    "GEM_HOST_API_KEY",
    "CARGO_REGISTRY_TOKEN",

    // VCS / CI
    "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN",
    "GITLAB_TOKEN", "CI_JOB_TOKEN",

    // Secrets managers
    "VAULT_TOKEN",

    // Misc high-value
    "DOCKER_PASSWORD", "DOCKER_AUTH_CONFIG",
    "SNYK_TOKEN", "CODECOV_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HUGGING_FACE_HUB_TOKEN",
}
```

This list is deliberately a denylist of literal names. Adding a new known
credential variable is a one-line change here; broadening to pattern matching is
a per-profile opt-in, not a default.

### Protected essential variables (never scrubbed)

A small hardcoded allowlist guards core process variables so a profile that
opts into broad `deny` globs cannot accidentally break execution. These are
never scrubbed regardless of deny patterns:

```
PATH, HOME, USER, LOGNAME, SHELL, PWD, OLDPWD, TERM, TMPDIR, TEMP, TMP,
LANG, LC_*, TZ, DISPLAY, HOSTNAME, NODE_ENV
```

The built-in literal deny list does not touch these names; the protected set is
the safety net for the moment a user adds a wildcard deny like `"*_TOKEN"` to a
profile.

## 6. Per-profile allow lists (avoiding developer friction)

Each restrictive profile gains an `environment.allow` block re-permitting only
its ecosystem's legitimately required variables. This is the mechanism behind
the accepted-risk trade-off in §2.

- **`npm-restrictive.yml`** (npm, pnpm, yarn, bun, npx, pnpx):
  ```yaml
  environment:
    allow:
      - NPM_TOKEN
      - NPM_AUTH_TOKEN
      - NODE_AUTH_TOKEN
      - npm_config_*          # npm lowercases config-derived vars
      - NPM_CONFIG_*
      - NODE_EXTRA_CA_CERTS
  ```
  Result: a malicious JS install hook can read `NPM_TOKEN`, but `AWS_*`,
  `TWINE_*`/PyPI tokens, `GITHUB_TOKEN`, and `VAULT_*` remain scrubbed.

- **`pypi-restrictive.yml`** (pip, uv, ...):
  ```yaml
  environment:
    allow:
      - TWINE_USERNAME
      - TWINE_PASSWORD
      - TWINE_REPOSITORY*
      - PIP_*
      - UV_*
      - POETRY_*
  ```
  Result: a malicious Python package can read its PyPI publishing creds, but
  not `NPM_TOKEN` or `AWS_*`.

- **`pnpm-restrictive.yml`**: same allow set as npm.
- **`npx.yml`**: npm allow set (npx executes npm-ecosystem code).

Each profile's allow list should be reviewed so it grants the **minimum** set of
variables the package manager needs for auth, registry config, and TLS.

## 7. Runtime overrides (`--sandbox-allow`) and project overlays

Every other resource type (read, write, exec, net-connect, net-bind) is tunable
three ways that all converge on the resolved policy: the profile YAML, a
one-off CLI `--sandbox-allow type=value`, and a persisted per-repo overlay
(`pmg sandbox allow`, stored under `SandboxOverlayDir()`). Environment
protection must be consistent with this model, otherwise a developer who hits a
scrubbed variable would have no escape hatch short of editing a profile file.

### 7.1 New allow type: `env`

Add `SandboxAllowEnv SandboxAllowType = "env"` to the existing enum in
`config/config.go`, so users can write:

```bash
pmg --sandbox-allow env=NPM_TOKEN npm install      # one-off
pmg sandbox allow env=NPM_TOKEN                     # persist for this repo
```

- `config/sandbox_allow.go` (`parseSingleOverride`) accepts the `env` type.
  **Crucially, the value is taken literally as a variable-name pattern and is
  NOT path-resolved or host:port-parsed** the way `read`/`write`/`net-*` values
  are. An `env` value is a name or glob (e.g. `NPM_TOKEN`, `npm_config_*`).
- `sandbox/executor/apply.go` (`applyRuntimeOverrides`) gains an `env` case that
  appends the value to `policy.Environment.Allow`:

  ```go
  case config.SandboxAllowEnv:
      log.Infof("Sandbox override: allowing environment variable %s", override.Value)
      policy.Environment.Allow = append(policy.Environment.Allow, override.Value)
  ```

  Unlike the filesystem cases, there is **no `removeExactMatch` on a deny
  list**: env uses allow-wins semantics (§8), so appending to `Allow` is
  sufficient to un-scrub a variable regardless of whether it was denied by the
  built-in list or a profile `deny` glob. This is simpler than — and
  intentionally different from — the filesystem model, where deny shadows allow
  and so an exact deny entry must be removed.

### 7.2 Overlays

Overlays already persist generic `OverlayAllow{Type, Value}` entries and replay
them through `applyRuntimeOverrides` via `ToAllowOverrides()`. Once `env` is a
valid allow type, overlays carry env allowances with **no overlay schema
change** (`OverlaySchemaVersion` stays 1) — `pmg sandbox allow env=NPM_TOKEN`
writes an `env` entry that is applied on every run in that repo. The overlay
`Value` is stored and replayed verbatim, which is correct here precisely because
env values are not path-normalized.

### 7.3 Allow-only, and governed by lockdown

- Overrides and overlays are **allow-only** by design (they widen access). There
  is deliberately no `--sandbox-allow`/overlay form that *adds* a deny; tightening
  is done in the profile `environment.deny`. This matches every existing type.
- The `env` allow override is **security-sensitive** (it re-exposes a
  credential), so it inherits the existing governance unchanged: `--sandbox-allow`
  is already a managed/governed flag, so under `global_lockdown` a CLI `env=`
  allow is refused, and `applyProjectOverlay` already ignores overlays when
  `cfg.IsLocked()`. A locked managed baseline can therefore **forbid
  un-scrubbing** a variable, which is the desired property for centrally managed
  fleets. No additional governance code is needed; the spec only requires that
  the new type flow through these existing checks (covered by tests in §10).

### 7.4 No violation-driven auto-suggestion

The `read`/`write`/`exec` flows can suggest an override after a sandbox
*violation* (`BuildAllOverrides` / `overrideSuggestion`). Env scrubbing produces
**no such violation**: the variable is simply absent, and the child may later
fail for an unrelated-looking reason (e.g. "npm ERR! 401 Unauthorized"). We do
**not** fabricate a synthetic violation for env. Instead, discoverability comes
from audit logging (§9): the scrubbed variable **names** are logged, so a user
who sees an auth failure can find the "scrubbed NPM_TOKEN" line and run
`--sandbox-allow env=NPM_TOKEN`. The docs (`docs/sandbox.md`) must spell out this
remediation explicitly since there is no automatic suggestion.

## 8. Matching semantics

- Matching is on the variable **name** (the substring left of the first `=` in
  each `KEY=VALUE` entry).
- Patterns are **case-insensitive** globs (reuse `sandbox/util` glob matching;
  Miasma-style scrambling targets conventionally uppercase names, but
  case-insensitivity removes a trivial bypass and matches lowercase
  `npm_config_*`).
- An entry is **scrubbed** (removed entirely, not blanked) iff:
  `matches(effectiveDeny) AND NOT matches(allow) AND NOT isProtectedEssential`.
- `effectiveDeny = DANGEROUS_ENV_VARS ∪ policy.Environment.Deny` (the latter
  already merged from inheritance; deny is profile-only — overlays/CLI cannot add
  denies, see §7.3).
- `allow = policy.Environment.Allow`, which by the time `ScrubEnv` runs already
  includes profile allows **plus** any overlay and `--sandbox-allow env=` entries
  merged in by `applyProjectOverlay` / `applyRuntimeOverrides`. **Allow wins over
  deny** (built-in or profile).
- Removal (vs. setting empty) is intentional: absence is the cleanest "not set"
  signal and avoids tools that treat empty-string specially.

### Proposed API (in `sandbox/util`)

```go
type EnvScrubOptions struct {
    Allow []string // profile environment.allow (already merged)
    Deny  []string // profile environment.deny (already merged)
}

type EnvScrubResult struct {
    Env     []string // kept entries (KEY=VALUE)
    Removed []string // removed variable NAMES only (never values), for audit
}

// ScrubEnv removes sensitive variables from env per the built-in
// DANGEROUS_ENV_VARS list extended by opts.Deny and suppressed by opts.Allow.
func ScrubEnv(env []string, opts EnvScrubOptions) EnvScrubResult
```

This parallels `GetMandatoryDenyPatterns` and keeps all matching logic in
`sandbox/util` where `DANGEROUS_FILES` already lives, so the linter and tests
have a single source of truth.

## 9. Audit and observability

- `ScrubEnv` returns the **names** of removed variables (never values).
- `executor.ApplySandbox` logs the scrubbed count at info and the names at
  debug, and threads them into the existing sandbox `ExecutionResult` so they
  can be surfaced in the event log alongside other sandbox decisions.
- Emitting "credential variable present and scrubbed during install" into the
  eventlog gives defenders a signal that a package run had access to (and was
  denied) sensitive variables — useful even when nothing malicious is observed.

## 10. Testing

- `sandbox/util`: table-driven tests for `ScrubEnv` covering deny match, allow
  suppression, protected-essential preservation, case-insensitivity, profile
  glob denies, and removal-vs-blank. Use `testify` `assert`/`require` per repo
  conventions.
- `sandbox/policy_test.go`: `Environment` merge under inheritance (union of
  allow/deny, parent + child).
- `executor`: env is scrubbed when sandbox enabled; untouched when the policy is
  disabled for the PM; PTY and direct paths both receive the scrubbed slice.
- Profile fixtures: assert npm profile keeps `NPM_TOKEN` and drops `AWS_*` /
  `TWINE_PASSWORD`; pypi profile keeps `TWINE_*` and drops `NPM_TOKEN` / `AWS_*`
  (encodes the §2 accepted-risk contract as a regression test).
- **Override parsing** (`config/sandbox_allow_test.go`): `env=NPM_TOKEN` parses
  to `SandboxAllowEnv` with the value kept verbatim (no path resolution); a glob
  value like `env=npm_config_*` is preserved.
- **Override application** (`sandbox/executor`): `--sandbox-allow env=AWS_PROFILE`
  un-scrubs an otherwise-denied variable; allow-wins holds even against a
  profile `deny` glob.
- **Overlay round-trip**: an `env` allow saved to an overlay is replayed on the
  next run and un-scrubs the variable, with `OverlaySchemaVersion` unchanged.
- **Governance**: under `global_lockdown`, a CLI `--sandbox-allow env=` is
  refused and an overlay `env` entry is ignored, so a locked baseline keeps the
  variable scrubbed.

## 11. Rollout / compatibility

- Backward compatible: profiles without an `environment:` block still get the
  built-in `DANGEROUS_ENV_VARS` default deny once sandbox is enabled. Existing
  configs need no change.
- The built-in deny list is literal known names only, so false positives are
  unlikely. If a niche build step relied on one of those exact names, the escape
  hatches are the per-PM `environment.allow`, a one-off `--sandbox-allow
  env=NAME`, or a persisted overlay — all surfaced by the audit log of scrubbed
  names so the cause is obvious.
- Document in `docs/sandbox.md`: the default deny list, the per-profile allow
  mechanism, the `--sandbox-allow env=` / `pmg sandbox allow env=` escape hatch
  and its remediation message, and the accepted-risk trade-off.

## 12. Future enhancements

Captured from the broader analysis; out of scope for v1 but natural follow-ups.

1. **Always-on (sandbox-independent) enforcement.** Scrub env even when the OS
   sandbox is unavailable or disabled, since env filtering needs no platform
   primitive. Highest-value extension; deferred only to avoid changing the
   current "sandbox off = no protection" contract without explicit opt-in.
2. **Default-deny-all (allowlist-only) env mode.** An opt-in strict tier
   (`environment.default_deny: true`) that starts from an empty environment and
   passes only an allowlist (`PATH`, `HOME`, `npm_config_*`, proxy/CA vars, ...),
   implemented via `--clearenv`/`--setenv` on Linux. Best suited to CI, where
   the environment is narrow and knowable. Strongest defense against novel
   variable names but higher friction.
3. **Linux `/proc` hardening.** The Miasma worm dumps GitHub Actions runner
   memory via `/proc` to obtain "secrets not exposed as env vars." Pair env
   scrubbing with PID-namespace isolation (already `unsharePID: true`) plus
   masking other processes' `environ`/`mem` (e.g. `hidepid`/minimal proc mount)
   so scrubbing cannot be sidestepped through `/proc`.
4. **Sandbox-detection hardening.** Miasma fingerprints analysis environments
   via known fake env vars; ensure PMG does not inject identifiable markers into
   the child environment that aid evasion.
5. **Audit-only mode.** A non-enforcing mode that logs which sensitive variables
   *would* be scrubbed, to size impact before turning enforcement on.
6. **Egress note (defense-in-depth only).** Network allow/deny is explicitly
   *not* a primary control for this threat because exfil rides allowlisted
   `github.com`; keep it as layered defense, not a substitute for scrubbing.
