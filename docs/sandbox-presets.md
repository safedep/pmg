# Sandbox Presets

A preset is a named bundle of sandbox allowances for one workload. For
example: what `lint-staged` needs from git, or what `astro dev` needs to
write and bind. Any tool with a known sandbox footprint can have a preset.
Presets add allowances without removing authored deny-list entries.
Filesystem denies still apply, subject to the driver's path-matching limits.
Network allowances have the precedence limits described below.
A preset can opt out of three built-in protections through its YAML.

- It can allow reading `.git/config`.
- An exact `${CWD}/.git` or `${HOME}/.git` write entry suppresses the mandatory whole-directory write deny.
  The `git` preset uses this opt-out.
  Top-level hooks and config retain separate denies, but submodule hooks and config under `.git/modules` can become writable.
- It can preserve specific credential variables by exact name.

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

Apply presets from the project root to save them in the per-repository overlay.

```bash
pmg sandbox allow preset=git preset=astro
```

Every sandboxed PMG run in that repository applies the overlay.
Package-manager sandboxing is off by default.
Enable it with `--sandbox` or `sandbox.enabled: true`.
`pmg sandbox exec` always uses a sandbox.

For one run, use a runtime preset reference instead.

```sh
pmg --sandbox --sandbox-allow preset=pip-user pip install --user example
pmg --sandbox-allow preset=claude sandbox exec -- claude
```

Agent presets can preserve API keys and allow writes to agent state.
A saved overlay has no package-manager scope.
A later sandboxed install script in this repository receives those allowances too.
The agent presets' threat notes rely in part on denies supplied by `exec`, which npm and PyPI base profiles do not supply.
An install script can then receive an agent API key and writable hook or state files.
Preset references also bypass the sensitive-variable `--force` check.
Prefer one-run agent presets or an exec-only custom profile.
Even under exec, some writable agent state can enable future command execution.
Read the threat notes and [exec guide](sandbox-exec.md) before use.

Or attach presets permanently to a custom sandbox profile:

```yaml
# <config-dir>/sandbox/profiles/pnpm-custom.yml
name: pnpm-custom
inherits: pnpm
package_managers: [pnpm]
presets: [git, astro]
```

Use `pmg setup info` to find the config directory.
Linux normally uses `~/.config/safedep/pmg`.
macOS uses `~/Library/Application Support/safedep/pmg`.
Select the custom profile through `sandbox.policies.pnpm.profile: pnpm-custom`, or with `--sandbox-profile pnpm-custom` for one run.

Under [lockdown](config.md#lockdown), PMG ignores the user preset directory and repository overlays.
It refuses `pmg sandbox allow` saves and runtime sandbox-allow overrides.
A managed profile reference must resolve in its managed registry.
A dependency on a user-only preset fails profile loading.

Presets are applied by reference: upgrading PMG (or editing a user preset)
updates the allowances everywhere the preset is used.
A missing profile-referenced preset fails profile loading.
A missing runtime or overlay preset warns and continues with fewer allowances.
PMG skips invalid user preset files, which can then appear missing.

## Available official presets

| Preset     | For                                                        |
| ---------- | ---------------------------------------------------------- |
| `git`      | lint-staged, husky, turbo, changesets                      |
| `astro`    | Astro dev server and build                                 |
| `vite`     | Vite dev server and build                                  |
| `nextjs`   | Next.js dev server and build                               |
| `asdf`     | asdf version manager tool installs                         |
| `claude`   | Claude Code under `pmg sandbox exec`                       |
| `codex`    | Codex CLI under `pmg sandbox exec`                         |
| `pi`       | Pi agent under `pmg sandbox exec`                          |
| `pip-user` | `pip install --user` and the pip fallback to the user site |

## Creating your own preset

Scaffold, edit and validate:

```bash
pmg sandbox preset init myapp --author "Your Name" --label myapp
pmg sandbox preset edit myapp     # opens $VISUAL / $EDITOR, validates when the editor exits
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

An invalid edit stays on disk and PMG skips it at load time.
Use an editor that waits until editing finishes, such as `code --wait`.

Validate the file that `init` created.
Replace `<config-dir>` with the config directory in the path that `init` printed.
Keep the quotes if the path contains spaces.

```bash
pmg sandbox preset lint "<config-dir>/sandbox/presets/myapp.yml"
```

A bind entry also enables `allow_network_bind`.
On macOS, this permits binding every loopback port, not only the listed port.
Landlock currently does not restrict bind or listen at all.
Under `network_via_proxy_only`, the boolean also permits connections to every loopback port on both Seatbelt and Landlock.
A displayed `localhost:8080` entry is therefore not a single-port boundary.

Rules the schema enforces:

- `kind` must be `preset`.
  The lookup name comes from `name`, not the filename.
  Names match `[a-z0-9][a-z0-9-]*`.
  A preset needs at least one allowance.
  The current maximum `schema_version` is 1.
  Strict decoding rejects unknown fields.

- Allow-only sections: `filesystem.allow_read/allow_write`,
  `process.allow_exec`, `network.allow_bind`, `network.allow_outbound`,
  `environment.allow`. Deny rules and profile booleans are rejected.
- Paths must be anchored at `${CWD}/`, `${HOME}/` or `${TMPDIR}/`, no `..`,
  and must not name sensitive files (`.env`, `.ssh`, ...).
- Binds must be loopback (`localhost`, `127.0.0.1`, `[::1]`).
- `environment.allow` entries are exact variable names, no globs.
- `network.allow_outbound` entries are `host:port` rules the proxy reads,
  as in [Network rules](sandbox.md#network-rules). A rule names a host,
  such as `api.anthropic.com:443` or `*.anthropic.com:*`. The host `*` is
  refused, because a preset must not open the whole network. The rules add
  to the profile's allow list without removing a deny entry.
  PMG drops a preset allow only when one authored deny covers its entire host and port range.
  The catch-all deny `*:*` drops none,
  because a preset rule is meant to rise above it. A preset adds allowances
  and restricts nothing.
  A partial overlap can survive and win by specificity.
  For example, a more specific `host:*` preset allow can beat a `*.domain:443` or `*:443` authored deny.
  Use `--debug` or `--log <file>` to see drop warnings.
  Under the `exec` profile every destination is
  already allowed, so a preset rule matters once a profile denies `*:*`.
  A catch-all deny refuses other destinations only in `--network-mode enforce`.
  The default audit mode records matches and allows them.
  Proxy confinement is a separate control.
  A child profile can disable it with `network_via_proxy_only: false`.

Precedence and residual risks:

- A preset environment allowance covered by a profile-authored
  `environment.deny` pattern is dropped.
  Use `--debug` or `--log <file>` to see the warning. Surviving preset
  allowances still opt out of PMG's built-in credential variable scrubbing,
  which is their intended use.
- A preset filesystem allowance never removes a deny rule authored in a
  profile: deny wins over allow on every platform.
- The `git` preset allows reading `.git/config` and writing under `.git/`,
  but writes to `.git/config` and everything under `.git/hooks` stay
  covered by separate mandatory denies.
  Submodule hooks and config under `.git/modules` are not covered by that top-level protection.
  The `git` preset can make them writable.
  A planted submodule hook or `core.hooksPath` can run outside the sandbox on a later Git command.
- In a linked worktree, PMG mirrors grants covering the checkout's git directory into validated worktree and common directories.
  It repeats hooks and config restrictions there and denies writes to pointer files.
  This prevents worktree move and repair operations.
  See [worktrees](sandbox-exec.md) for details.

A preset name that collides with an official preset is shadowed — the
official one always wins. To propose an official preset, open a pull request
adding it under `sandbox/presets/` with threat notes and tests.
