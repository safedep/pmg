# Sandbox Presets

A preset is a named bundle of sandbox allowances for one workload. For
example: what `lint-staged` needs from git, or what `astro dev` needs to
write and bind. Any tool with a known sandbox footprint can have a preset.
Presets are **additive-only** — they can grant allowances on top of your
sandbox profile but can never remove a deny rule or weaken PMG's built-in
protections (`.git/hooks`, credential files and other mandatory denies stay
enforced).

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

## Contributing a preset

User presets live in `<config-dir>/sandbox/presets/` (e.g.
`~/.config/safedep/pmg/sandbox/presets/` on Linux). Drop a YAML file there:

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
  `process.allow_exec`, `network.allow_bind/allow_outbound`,
  `environment.allow`. Deny rules and profile booleans are rejected.
- Paths must be anchored at `${CWD}/`, `${HOME}/` or `${TMPDIR}/`, no `..`,
  and must not name sensitive files (`.env`, `.ssh`, ...).
- Binds must be loopback (`localhost`, `127.0.0.1`, `::1`).
- Outbound entries must be exact `host:port`, no wildcards.

A preset name that collides with an official preset is shadowed — the
official one always wins. To propose an official preset, open a pull request
adding it under `sandbox/presets/` with threat notes and tests.
