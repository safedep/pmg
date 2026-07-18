# Sandbox Presets

Status: Draft
Issue: https://github.com/safedep/pmg/issues/384

## Problem

Sandbox tuning is per-workload, not per-package-manager. The `pnpm` profile
cannot know a project runs `lint-staged` (needs `.git` access) or Astro (needs
`.astro/**` writes and a loopback bind). Issue #384 shows the resulting
lifecycle: opaque failure, manual overlay tuning, the next tool breaking, and
finally `sandbox.enabled false`. Users cannot judge whether an allowance is
safe; that judgment must ship with the allowance.

## Concept

A **preset** is a named, versioned, additive-only bundle of sandbox
allowances describing what one workload legitimately needs. Structurally, a
preset is exactly a reusable set of `pmg sandbox allow` entries: same trust
model, same enforcement mechanics, no new bypass channel.

```yaml
schema_version: 1
kind: preset
name: git
description: Git operations for hooks-driven tools (lint-staged, husky, turbo)
metadata:
  author: SafeDep
  labels: [git, hooks, javascript, python]
filesystem:
  allow_read:
    # Exact path suppresses the mandatory read deny. The write deny on
    # .git/config and all .git/hooks denies are not suppressible by this
    # preset (glob entries never suppress exact mandatory denies).
    - ${CWD}/.git/config
  allow_write:
    - ${CWD}/.git/**
```

The schema deliberately has no `deny_*` fields, no booleans
(`allow_pty`, `network_via_proxy_only`, ...), no `inherits` and no
`package_managers`. Decoding is strict: unknown fields are errors, so a
preset that tries to carry a deny rule fails to load.

## Attachment points

1. **Project overlay** (per repo):

   ```
   pmg sandbox allow preset=git preset=astro
   ```

   Stored by reference (`type: preset, value: git`) in the existing overlay
   file and resolved at apply time. Also usable as a one-off runtime flag:
   `--sandbox-allow preset=git`.

2. **Profile** (per package manager): a `presets:` list in profile YAML,
   resolved after `inherits`:

   ```yaml
   name: pnpm-custom
   inherits: pnpm
   package_managers: [pnpm]
   presets: [git, astro]
   ```

No built-in profile references a preset. Defaults are unchanged; the default
security posture does not move.

## Sources and resolution

Presets are loaded through an ordered list of sources behind a
`PresetSource` interface:

| Source  | Location                          | Trust                          |
| ------- | --------------------------------- | ------------------------------ |
| builtin | embedded in the pmg binary        | maintainer-reviewed, same trust as the enforcing code |
| user    | `<config>/sandbox/presets/*.yml`  | same trust as the user's own overlays; community presets are dropped here |

Name resolution walks sources in order; builtin wins and a user preset with
a colliding name is reported as shadowed (an official preset cannot be
silently replaced by a local file).

The source abstraction is the extension point for the roadmap: a hosted
community registry and SafeDep cloud sync are additional read-only sources
(e.g. a directory materialized by cloud config sync), not new mechanics.
`schema_version` gates forward compatibility: a preset with a newer schema
than the binary understands is rejected with a clear error.

## Metadata

`metadata.author` (string) and `metadata.labels` (string list) are first
class and filterable:

```
pmg sandbox preset list --label git --author SafeDep --json
```

Metadata is descriptive only; it never affects enforcement.

## Merge semantics

Preset sections map 1:1 onto the existing allow-override types:

| Preset field            | Override type |
| ----------------------- | ------------- |
| `filesystem.allow_read` | `read`        |
| `filesystem.allow_write`| `write`       |
| `process.allow_exec`    | `exec`        |
| `network.allow_outbound`| `net-connect` |
| `network.allow_bind`    | `net-bind` (also sets `allow_network_bind` so translators emit bind rules) |
| `environment.allow`     | `env`         |

Application order is unchanged from today: base profile chain → profile
`presets` → profile own rules → project overlay (including overlay presets)
→ `--sandbox-allow` flags. Entries are unioned with dedupe; exact matches in
the policy's own deny lists are removed (same rule as `pmg sandbox allow`);
mandatory denies still win everywhere except the existing exact-match
suppression in `GetMandatoryDenyPatterns`. `.git/hooks/**` remains
non-suppressible.

A preset referenced but not resolvable at apply time is a loud warning
(stderr + log), never a hard failure and never a silent no-op: missing
allowances fail closed.

## Validation (enforced at load and by `pmg sandbox preset lint`)

- `kind: preset`, bare lowercase name (`[a-z0-9-]+`), at least one rule.
- `schema_version` absent or `1`; newer versions rejected.
- Filesystem and exec paths must be anchored at `${CWD}/`, `${HOME}/` or
  `${TMPDIR}/`. Bare absolute paths, relative paths, `~` and `..` are
  rejected.
- Filesystem entries naming sensitive targets (`.env*`, `.npmrc`, `.ssh`,
  ...) are rejected via the existing sensitive-target classifier.
- `allow_bind` hosts must be loopback (`localhost`, `127.0.0.1`, `::1`);
  port may be numeric or `*`.
- `allow_outbound` entries must be exact `host:port`; no wildcards.
- `environment.allow` entries are name globs; a bare `*` is rejected.

Official presets additionally document their residual risk in YAML comments
(threat notes), making each preset a reviewable security document.

## CLI

```
pmg sandbox preset list [--label L]... [--author A] [--json]
pmg sandbox preset show <name> [--json]
pmg sandbox preset lint <file>...
pmg sandbox allow preset=<name> ...
```

`preset show` prints the effective allowances, metadata, source and, for
builtins, the embedded YAML including threat notes. `pmg sandbox project
show` and audit logs display preset entries with their type, preserving
provenance.

## Cloud / enterprise

- `global_lockdown` already refuses overlays entirely; overlay presets
  inherit that behavior. Profile presets referenced from managed
  configuration are admin-authored and allowed.
- Cloud-synced presets are a future `PresetSource` reading a directory
  materialized by SafeDep cloud config sync. Reference semantics (overlays
  store names, not snapshots) means centrally updated presets propagate on
  next run without touching per-repo state.

## Out of scope (v1)

- Hosted community registry and `pmg sandbox preset install`.
- Violation-signature → preset suggestion in the execution report
  (planned follow-up; presets make that hint actionable).
- Preset pinning/versioning beyond `schema_version`.

## Official presets shipped in v1

`git`, `astro`, `vite`, `nextjs`. Seeded from real tuning sessions
(issue #384 and maintainer overlays), each with threat notes.
