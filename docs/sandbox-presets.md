# Sandbox Presets

A preset is a named bundle of sandbox allowances for one workload. For
example: what `lint-staged` needs from git, or what `astro dev` needs to
write and bind. Any tool with a known sandbox footprint can have a preset.
Presets are **additive-only**: they grant allowances on top of your sandbox
profile and can never remove a deny rule. A profile-authored deny always
beats a preset allowance, and preset validation rejects paths that would
opt out of PMG's mandatory protections (`.git/hooks`, `.git/config` writes,
credential files). The two opt-outs a preset can perform, both visible in
its YAML: read access to `.git/config` (required for git to operate) and
un-scrubbing specific built-in credential variables by exact name.

## Using presets

Discover what's available:

```bash
pmg sandbox preset list
pmg sandbox preset list --label dev-server --author SafeDep
```

Inspect a preset before trusting it. The output is the preset's own YAML,
including its threat notes describing the residual risk of each allowance:

```bash
pmg sandbox preset show git
```

Apply presets to the current repository (run from the project root; this
saves into the per-repo overlay used by every future PMG run there):

```bash
pmg sandbox allow preset=git preset=astro
```

Or attach presets permanently to a custom sandbox profile:

```yaml
# ~/.config/safedep/pmg/sandbox/profiles/pnpm-custom.yml
name: pnpm-custom
inherits: pnpm
package_managers: [pnpm]
presets: [git, astro]
```

Presets are applied by reference: upgrading PMG (or editing a user preset)
updates the allowances everywhere the preset is used.

## Available official presets

| Preset   | For                                    |
| -------- | -------------------------------------- |
| `git`    | lint-staged, husky, turbo, changesets  |
| `astro`  | Astro dev server and build             |
| `vite`   | Vite dev server and build              |
| `nextjs` | Next.js dev server and build           |
| `asdf`   | asdf version manager tool installs     |

## Creating your own preset

Scaffold, edit and validate:

```bash
pmg sandbox preset init myapp --author "Your Name" --label myapp
pmg sandbox preset edit myapp     # opens $VISUAL / $EDITOR, validates on save
pmg sandbox allow preset=myapp    # apply to the current repo
```

User presets live in `<config-dir>/sandbox/presets/` (e.g.
`~/.config/safedep/pmg/sandbox/presets/` on Linux) — community presets are
installed by dropping a file there. `pmg sandbox preset list` always shows
where a preset came from: `builtin` (embedded in the pmg binary,
maintainer-reviewed) vs the user file path, and a user preset that reuses a
built-in name is marked `SHADOWED` — the built-in always wins, so an
official preset cannot be silently replaced. A preset file looks like:

```yaml
kind: preset
name: myapp
description: What this preset enables, one line
metadata:
  author: Your Name
  labels: [myapp, dev-server]
# Threat notes: explain what each allowance permits and why it is acceptable.
filesystem:
  allow_write:
    - ${CWD}/.myapp/**
network:
  allow_bind:
    - localhost:8080
```

Validate it:

```bash
pmg sandbox preset lint ./myapp.yml
```

Rules the schema enforces:

- Allow-only sections: `filesystem.allow_read/allow_write`,
  `process.allow_exec`, `network.allow_bind`, `environment.allow`. Deny
  rules and profile booleans are rejected.
- Paths must be anchored at `${CWD}/`, `${HOME}/` or `${TMPDIR}/`, no `..`,
  and must not name sensitive files (`.env`, `.ssh`, ...).
- Binds must be loopback (`localhost`, `127.0.0.1`, `::1`).
- `environment.allow` entries are exact variable names, no globs.
- No `network.allow_outbound`: current sandbox drivers cannot enforce
  host-granular outbound rules (a single allow means blanket network
  access), so presets are not allowed to change outbound posture at all.

Precedence guarantees, in addition to PMG's mandatory denies:

- A preset environment allowance covered by a profile-authored
  `environment.deny` pattern is dropped with a warning. Surviving preset
  allowances still opt out of PMG's built-in credential variable scrubbing,
  which is their intended use.
- A preset filesystem allowance never removes a deny rule authored in a
  profile: deny wins over allow on every platform.
- The `git` preset allows reading `.git/config` and writing under `.git/`,
  but writes to `.git/config` and everything under `.git/hooks` stay
  blocked by mandatory denies on all platforms.

A preset name that collides with an official preset is shadowed — the
official one always wins. To propose an official preset, open a pull request
adding it under `sandbox/presets/` with threat notes and tests.
