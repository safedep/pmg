# Custom Block Messages and Package Blocklist

**Date:** 2026-07-08
**Status:** Approved

## Problem

PMG blocks installations for two reasons today: dependency cooldown and malicious
package detection. The block output is fixed. Organizations deploying PMG (typically
via managed config) want developers to see org-specific guidance when a block
happens — who to contact, where to request an exemption — so a block reads as
"your security team's policy" rather than an opaque tool failure.

Separately, organizations (and individual users) want to ban specific packages
outright — deprecated internally, known-bad, or policy-violating — independent of
malware verdicts.

## Requirements

### 1. Custom block messages (per control)

- A static, optional message per control, shown whenever that control blocks:
  - `dependency_cooldown.message` — shown on every cooldown block.
  - `malware.message` — shown on every malicious-package block (new top-level
    `malware:` config section; its only field for now).
- The message is **appended** to the existing built-in block output, never a
  replacement. No per-package or per-version templating — same text every time.
- The message is carried on every surface where PMG renders the corresponding
  block (see Design → Output surfaces). In PMG-rendered summary output it appears
  once per block event type per run (not repeated per package); in the proxy's
  per-request 403 body it necessarily repeats per request, which is acceptable —
  that body is relayed by the package manager's own error output.
- Unset/empty message = current behavior exactly.

### 2. Package blocklist

- New top-level `blocked_packages` list. Entry shape mirrors `trusted_packages`:

  ```yaml
  blocked_packages:
    - purl: pkg:npm/left-pad
      reason: "Deprecated internally; use String.prototype.padStart"
    - purl: pkg:npm/lodash@4.17.20
      reason: "CVE-2021-23337"
  ```

- Matching semantics identical to `trusted_packages`: a PURL without a version
  blocks **all** versions; a PURL with a version blocks that version only.
- Hard block — no interactive confirmation, no paranoid-mode dependency.
- The entry `reason` is surfaced in the block output and audit event.

### Precedence

For a concrete package version, controls are evaluated in this order:

1. `InsecureInstallation` → allow (explicit bypass-everything escape hatch; unchanged).
2. `blocked_packages` match → **block**. Block beats trust.
3. `trusted_packages` match → allow (unchanged).
4. Remaining controls (cooldown, malware analysis) as today.

## Design

### Config (`config/`)

- `DependencyCooldownConfig` gains `Message string` (`mapstructure:"message"`).
- New `MalwareConfig struct { Message string }`, wired as `Malware` on `Config`
  (`mapstructure:"malware"`).
- New `BlockedPackages []BlockedPackage` on `Config`
  (`mapstructure:"blocked_packages"`).
- `BlockedPackage` is a **distinct type** from `TrustedPackage` (same two fields:
  `PURL`, `Reason`). They stay separate so either can grow control-specific fields
  (e.g. trust expiry, blocklist alternatives) without breaking the other.
- The PURL parsing / preprocessed lookup / no-version-matches-all matching
  machinery currently inside `trusted.go` is extracted into a shared internal
  index in the `config` package, used by both `IsTrustedPackageRef` and a new
  `IsBlockedPackageRef` (returning the matched reason). No YAML key changes;
  full backward compatibility, no migration.
- `config.template.yml` documents all three additions, with the block-beats-trust
  precedence stated explicitly on `blocked_packages`.

### Proxy flow (`proxy/interceptors/`)

- The blocklist check is a **fast-path gate**: it runs where `fastAllow` runs in
  `base_registry.go`, before `analyzePackage` — no analyzer gRPC call, no cache
  involvement, no circuit-breaker traffic for blocklisted packages. The existing
  gate becomes a single policy gate implementing the precedence order above,
  keeping one call site per concrete interceptor.
- A blocklist hit returns `ActionBlock` with a `BlockMessage` built from the
  entry's `reason`, clearly labeled as a policy block (not a malware verdict).
- No metadata stripping: if a semver range resolves to a blocked version, the
  install fails with the block message rather than PMG steering the package
  manager to another version. Deliberate for v1 — the blocklist itself never
  silently steers. Cooldown-style metadata stripping is a possible future
  enhancement.
- Known interaction: cooldown interceptors strip metadata before the registry
  interceptor sees a concrete-version request, so a blocked version that is also
  inside its cooldown window may be steered away by cooldown before the blocklist
  ever fires. That is existing cooldown behavior and acceptable; the blocklist
  guarantee is that a blocked version is never *installed*, not that every block
  is attributed to the blocklist.

### Guard flow (`guard/`)

- The resolved dependency graph is checked against `blocked_packages` before any
  malware analysis calls **and before the existing trusted-package skip**
  (the Precedence order applies identically in both flows); matches block the
  install with the same reason surfaced.

### Audit

- New audit event type for blocklist blocks (e.g. `package_blocklist_blocked`) so
  event logs and cloud sync distinguish policy blocks from malware blocks.

### Output surfaces (`internal/ui/`, proxy `BlockMessage`)

Blocks surface on three distinct surfaces today; the custom message must be
carried on each one that renders the corresponding block:

1. **Report sections (`internal/ui/report.go`, normal/verbose):** custom messages
   render as an extra line appended under the existing block summary sections —
   `dependency_cooldown.message` under the cooldown section, `malware.message`
   under the malicious-package section. Once per block event type per run.
2. **Silent-mode report output (`internal/ui/report.go` `reportSilent`):**
   today `reportSilent` prints nothing, and the `Block` interaction callback
   (`ui.BlockNoExit` → `blockWithExit`) that used to print blocks is populated
   by the guard flow but never invoked — a dead path. So in silent mode a block
   currently produces no PMG output at all, violating PMG's own documented
   silent contract ("hidden except for errors and malicious package
   detection"). Fix as part of this work: `reportSilent` renders the
   malware-block and blocklist-block sections (with `malware.message`
   appended) when the outcome is blocked. Cooldown blocks stay hidden in
   silent mode (matching the documented contract); `blockWithExit` is left
   unchanged. This one rendering path covers both guard and proxy flows.
3. **Proxy 403 body (`BlockMessage`):** `malware.message` is appended to the
   malware block body (`base_registry.go`), and the blocklist block body carries
   the entry `reason`. The Go cooldown handler (`go_cooldown.go`) is the one
   cooldown path that returns a 403 body (npm/pypi cooldown only strips
   metadata); `dependency_cooldown.message` is appended there. Per-request by
   nature; relayed via the package manager's own error output.

Additionally:

- Blocklist blocks get their own report section (like cooldown's), listing each
  blocked package with its `reason`.
- Stats/summary structures carry the blocklist outcome so the final
  `Installation blocked — …` line accounts for it.

## Testing

- `config/`: parse/merge/template tests for the three new fields, following
  existing patterns (`config_template_test.go`, `trusted_test.go`).
- `test/proxye2e/` (mandatory per repo policy — this is a new proxy-flow control):
  - Blocklisted package blocked: all-versions entry and version-pinned entry.
  - Block wins over trust: package in both lists is blocked.
  - Blocklisted package produces no analyzer call (fast-path verified via the
    stub malysis client).
  - Insecure-installation bypass still wins over the blocklist.
  - `dependency_cooldown.message` appears in the Go cooldown 403 body.
- `guard/`: guard-flow test asserting a blocklisted package blocks before trusted
  skip and before analysis.
- `internal/ui`: report tests asserting custom messages are appended for cooldown
  and malware block outcomes, blocked outcomes render in silent mode
  (`reportSilent`), and messages are absent when unset.

## Out of scope

- Version ranges, wildcards, or namespace patterns in `blocked_packages`.
- Per-package or templated custom messages.
- A custom message for blocklist blocks (per-entry `reason` covers it).
- Metadata stripping for blocked versions (future enhancement).
- Removing the dead `Block` interaction path (`PackageManagerGuardInteraction.Block`,
  `ui.Block`/`ui.BlockNoExit`/`blockWithExit`, and the unconsumed `blockConfig`
  plumbing in `guard/guard.go`). Confirmed dead in production; worth a follow-up
  cleanup once `reportSilent` is the established block-rendering path.
