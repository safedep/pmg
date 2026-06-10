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
   a list of case-insensitive name glob patterns covering known credential
   variables plus broad catch-alls (`*_TOKEN`, `*_SECRET`, ...). The catch-alls
   are what defend against the *scrambled / novel variable name* technique: we
   match on the shape of secret-bearing names, not a fixed enumeration.

2. **Per-profile `environment:` section** — each sandbox policy may declare
   additional `deny` patterns and `allow` patterns. `allow` suppresses matching
   built-in or profile denies (allow always wins), letting each ecosystem
   re-permit the variables its package manager legitimately needs.

Enforcement is a single chokepoint: after the sandbox policy is resolved in
`executor.ApplySandbox`, the resolved environment policy is applied to
`cmd.Env`, removing denied variables before the child process is spawned.
`ApplySandbox` is already the shared entry point for both the guard and proxy
flows and runs before the direct and PTY launch paths, so one integration point
covers every package-manager child PMG spawns.

```
os.Environ()
  -> shim.FilterPMGFromEnv()        (existing: strips PMG_SHIM_PATH, ~/.pmg/bin)
  -> mergeEnv(overrides)            (existing)
  -> [cmd.Env set in runner]
  -> executor.ApplySandbox():
        resolve policy
        cmd.Env = util.ScrubEnv(cmd.Env, allow, deny)   <-- NEW
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
  # DANGEROUS_ENV_VARS default deny list. Case-insensitive globs.
  deny:
    - MY_CUSTOM_SECRET

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

Lives next to `DANGEROUS_FILES` in `sandbox/util/dangerous.go`. Case-insensitive
name globs. Indicative starting set (to be finalized in implementation review):

```go
var DANGEROUS_ENV_VARS = []string{
    // Cloud providers
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_*",
    "AZURE_*", "ARM_*",
    "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_*", "GCP_*", "GCLOUD_*",

    // Package registry / publishing tokens
    "NPM_TOKEN", "NPM_AUTH_TOKEN", "NODE_AUTH_TOKEN",
    "TWINE_USERNAME", "TWINE_PASSWORD", "TWINE_*",
    "PYPI_*", "UV_PUBLISH_TOKEN", "FLIT_PASSWORD",
    "POETRY_PYPI_TOKEN_*", "POETRY_HTTP_BASIC_*",
    "GEM_HOST_API_KEY", "RUBYGEMS_*",
    "CARGO_REGISTRY_TOKEN", "CARGO_REGISTRIES_*",

    // VCS / CI
    "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN",
    "GITLAB_TOKEN", "CI_JOB_TOKEN",

    // Secrets managers
    "VAULT_TOKEN", "VAULT_*",

    // Misc high-value
    "DOCKER_PASSWORD", "DOCKER_AUTH_CONFIG",
    "SNYK_TOKEN", "CODECOV_TOKEN", "NPM_CONFIG__AUTH",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HUGGING_FACE_HUB_TOKEN",

    // Broad catch-alls — defend against scrambled / novel secret names
    "*_TOKEN", "*_SECRET", "*_PASSWORD", "*_API_KEY", "*_APIKEY",
    "*_ACCESS_KEY", "*_PRIVATE_KEY", "*_CREDENTIALS",
}
```

### Protected essential variables (never scrubbed)

A small hardcoded allowlist guards core process variables so a careless or
broad profile `deny` cannot break execution. These are never scrubbed
regardless of deny patterns:

```
PATH, HOME, USER, LOGNAME, SHELL, PWD, OLDPWD, TERM, TMPDIR, TEMP, TMP,
LANG, LC_*, TZ, DISPLAY, HOSTNAME, NODE_ENV
```

(The broad catch-alls above do not match these names today; the protected set
is a safety net against future or profile-supplied deny patterns.)

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

## 7. Matching semantics

- Matching is on the variable **name** (the substring left of the first `=` in
  each `KEY=VALUE` entry).
- Patterns are **case-insensitive** globs (reuse `sandbox/util` glob matching;
  Miasma-style scrambling targets conventionally uppercase names, but
  case-insensitivity removes a trivial bypass and matches lowercase
  `npm_config_*`).
- An entry is **scrubbed** (removed entirely, not blanked) iff:
  `matches(effectiveDeny) AND NOT matches(allow) AND NOT isProtectedEssential`.
- `effectiveDeny = DANGEROUS_ENV_VARS ∪ profile.environment.deny`.
- `allow = profile.environment.allow`. Allow wins over deny.
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

## 8. Audit and observability

- `ScrubEnv` returns the **names** of removed variables (never values).
- `executor.ApplySandbox` logs the scrubbed count at info and the names at
  debug, and threads them into the existing sandbox `ExecutionResult` so they
  can be surfaced in the event log alongside other sandbox decisions.
- Emitting "credential variable present and scrubbed during install" into the
  eventlog gives defenders a signal that a package run had access to (and was
  denied) sensitive variables — useful even when nothing malicious is observed.

## 9. Testing

- `sandbox/util`: table-driven tests for `ScrubEnv` covering deny match, allow
  suppression, protected-essential preservation, case-insensitivity, glob
  catch-alls, and removal-vs-blank. Use `testify` `assert`/`require` per repo
  conventions.
- `sandbox/policy_test.go`: `Environment` merge under inheritance (union of
  allow/deny, parent + child).
- `executor`: env is scrubbed when sandbox enabled; untouched when the policy is
  disabled for the PM; PTY and direct paths both receive the scrubbed slice.
- Profile fixtures: assert npm profile keeps `NPM_TOKEN` and drops `AWS_*` /
  `TWINE_PASSWORD`; pypi profile keeps `TWINE_*` and drops `NPM_TOKEN` / `AWS_*`
  (encodes the §2 accepted-risk contract as a regression test).

## 10. Rollout / compatibility

- Backward compatible: profiles without an `environment:` block still get the
  built-in `DANGEROUS_ENV_VARS` default deny once sandbox is enabled. Existing
  configs need no change.
- The built-in deny list is conservative for the package-manager context, but
  the broad catch-alls (`*_TOKEN`, etc.) may scrub a variable a niche build
  step relied on. Mitigation: the per-PM `environment.allow` escape hatch and
  clear audit logging of scrubbed names so the cause is obvious.
- Document in `docs/sandbox.md`: the default deny list, the per-profile allow
  mechanism, and the accepted-risk trade-off.

## 11. Future enhancements

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
