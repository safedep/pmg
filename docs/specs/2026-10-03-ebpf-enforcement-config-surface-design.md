# Configuration surface for kernel enforcement

Status: proposal, revision 1. Follows the enforcement design in
[2026-10-03-ebpf-proxy-enforcement-design.md](./2026-10-03-ebpf-proxy-enforcement-design.md),
which PR #507 implements. Nothing here changes PR #507.

## Problem

PR #507 puts the enforcement policy under `proxy.server.enforce` in the config
file. Of its eight keys, only `enabled` is reachable in another way: the
`--enforce` flag, the `PMG_PROXY_SERVER_ENFORCE_ENABLED` variable, and the
`enforce` input of the action. `ports`, `eligible_users`, `exempt_users`,
`exempt_executables`, `skip_destinations`, `cgroup` and `deny_udp` live in the
file only. The env mapping is an explicit table, so no variable exists for
them. The hidden `--enforce-exempt-executable` flag carries the runner globs
from the parent to the daemon and is not for users.

The file is the wrong surface for two of the three places enforcement runs:

- In CI the common need is "exempt this one agent binary" or "skip this one
  CIDR". A job should not have to ship a config file for one list entry.
- On a workstation the root daemon does not read the file the user edits.

The second point is the one a user hits first. `config/config.go` resolves the
config directory as `PMG_CONFIG_DIR`, then root's own home under sudo, then the
caller's home (`configDir`, line 829). `resolveConfigFile` (line 883) then makes
`/etc/safedep/pmg/config.yml` authoritative when it exists and ignores every
per-user file. So `sudo pmg proxy start --enforce` reads:

1. `/etc/safedep/pmg/config.yml` when it exists. PMG calls this the managed
   config. Only `sudo pmg setup install --system` writes it.
2. Otherwise `/root/.config/safedep/pmg/config.yml`, the per-user file of root.

It never reads `~/.config/safedep/pmg/config.yml` of the user who ran sudo.
The sudo guard exists so that an elevated run never obeys a file an
unprivileged user can write. The guard is correct. The consequence is that
`pmg config edit` as the user edits a file the daemon never sees, and nothing
says so.

`sudo pmg config edit` does not reach the managed config either:

- Without a managed file it opens root's per-user file. The daemon reads that
  file, so the edit takes effect, but it is root's personal config, not the
  system one, and the command does not say which file it opened.
- With a managed file it refuses: "configuration is globally managed and
  cannot be changed" (`runEdit`, `cmd/config/config.go`). `config set` refuses
  the same way. PMG then has no command that changes the managed file. The
  only path is to edit `/etc/safedep/pmg/config.yml` by hand.

Three files can plausibly hold the policy, and `pmg proxy status` shows the
policy the kernel got, not where it came from.

## Goal

An operator can see which file an enforcing daemon reads, can change the
system config with a `pmg` command, and can set every policy key from the
command line, the environment, and the action, with the precedence the config
doc already states: flags, then environment, then file, then defaults.

## Non-goals

- A new config format or a new file location. The managed file stays the
  fleet mechanism. `global_lockdown` keeps its meaning.
- Letting an unprivileged user change the policy of a root daemon. Every
  surface below is root-only where it touches the system config or an
  enforcing daemon.
- Reloading the policy of a running daemon. A change still needs a restart.

## Design

The four parts are independent. Part 1 is the smallest and removes the
surprise on its own. Parts 2 and 3 are the editing and the start surfaces.
Part 4 is the action and needs part 3.

### 1. Show the source

The daemon records the path of the config file it loaded in the state file,
prints it in the start message, and `pmg proxy status` prints it under the
enforcement block:

```
Kernel enforcement: active (cgroup /sys/fs/cgroup, ports 80,443)
  config: /etc/safedep/pmg/config.yml (managed)
```

The label after the path is one of `managed`, `root per-user`, `user`, or
`PMG_CONFIG_DIR`.

When `sudo pmg proxy start --enforce` falls back to root's per-user file, the
parent prints one warning before it detaches:

```
⚠ Reading root's per-user config at /root/.config/safedep/pmg/config.yml.
  A system daemon normally reads /etc/safedep/pmg/config.yml.
  Run `sudo pmg config edit --system` to create it.
```

The warning is recorded in the state file like the Docker and sudo warnings,
so `pmg proxy status` repeats it.

### 2. A system scope for `pmg config`

`pmg config edit`, `config set` and `config get` gain `--system`. With the
flag they operate on `/etc/safedep/pmg/config.yml`:

- `--system` needs root. Without root the command fails with
  `PermissionDenied` and the help text names `sudo`.
- A missing file is created from the template through the path that
  `WriteSystemTemplateConfig` already uses, so the directory and file get the
  same ownership and mode checks (`PrepareSystemDir`,
  `RequireTrustedSystemFile`). An existing file that PMG did not write is
  refused with the same error as today.
- `global_lockdown` does not block `--system`. The lock protects the managed
  file from users and from env and flag overrides. Root editing the managed
  file is the administrator changing policy, which is what the lock exists to
  reserve for the administrator.

Without `--system`, `sudo pmg config edit` and `sudo pmg config set` refuse
instead of editing root's per-user file in silence:

```
Error: under sudo, pmg config edit would open root's per-user config at
/root/.config/safedep/pmg/config.yml. Use `--system` for the managed config at
/etc/safedep/pmg/config.yml, or run the command without sudo for your own.
```

The managed-config refusal for a plain user stays as it is.

`pmg config path` is new. It prints the active config file and why:

```
/etc/safedep/pmg/config.yml (managed, authoritative)
```

```
/home/alice/.config/safedep/pmg/config.yml (user)
  ignored by a root daemon: it reads /root/.config/safedep/pmg/config.yml
  or /etc/safedep/pmg/config.yml when that exists
```

The second line appears only when the active file is a user file, so a user
learns before they start a daemon that their file is not the daemon's.

### 3. Flags and variables for the policy keys

`pmg proxy start` gains one flag per key. The names follow the config path:

| Config key | Flag | Variable |
| --- | --- | --- |
| `ports` | `--enforce-port` (repeatable) | `PMG_PROXY_SERVER_ENFORCE_PORTS` |
| `eligible_users` | `--enforce-eligible-user` (repeatable) | `PMG_PROXY_SERVER_ENFORCE_ELIGIBLE_USERS` |
| `exempt_users` | `--enforce-exempt-user` (repeatable) | `PMG_PROXY_SERVER_ENFORCE_EXEMPT_USERS` |
| `exempt_executables` | `--enforce-exempt-executable` (repeatable) | `PMG_PROXY_SERVER_ENFORCE_EXEMPT_EXECUTABLES` |
| `skip_destinations` | `--enforce-skip-destination` (repeatable) | `PMG_PROXY_SERVER_ENFORCE_SKIP_DESTINATIONS` |
| `cgroup` | `--enforce-cgroup` | `PMG_PROXY_SERVER_ENFORCE_CGROUP` |
| `deny_udp` | `--enforce-deny-udp` | `PMG_PROXY_SERVER_ENFORCE_DENY_UDP` |

The hidden `--enforce-exempt-executable` becomes the public flag. The parent
keeps using it to pass the runner globs to the daemon child, so the plumbing
stays as it is. A list variable holds comma-separated values.

List flags and variables add to the file's list. They never replace it. The
file carries the baseline an administrator set, and a flag must not be able
to drop a skip destination or an exempt user from it. Scalar flags and
variables override the file, as every other PMG flag does. The precedence is
the one the config doc states: flags, then variables, then file, then
defaults.

A flag that widens exemptions is a governed flag under `global_lockdown`:
`--enforce-eligible-user`, `--enforce-exempt-user`,
`--enforce-exempt-executable`, `--enforce-skip-destination` and
`--enforce-deny-udp=false` fail fast with the managed-config error, the same
as `--sandbox=false` does today. `--enforce-port` and `--enforce-cgroup` only
narrow or move the scope and stay allowed. The variables follow the same rule,
because the lock already disables `PMG_*` overrides.

Only root can start an enforcing daemon, so the flags give no new user a way
to change policy. The parent validates the flags in the preflight, before it
detaches, so a bad CIDR or an unknown user is reported at once.

### 4. Action inputs

The action gains four inputs, each a comma or newline separated list:

| Input | Flag it passes |
| --- | --- |
| `enforce-ports` | `--enforce-port` |
| `enforce-exempt-users` | `--enforce-exempt-user` |
| `enforce-exempt-executables` | `--enforce-exempt-executable` |
| `enforce-skip-destinations` | `--enforce-skip-destination` |

The action passes them as flags on the `sudo pmg proxy start --enforce` line.
Flags are explicit in the job log, where a variable preserved through sudo is
not. `eligible_users`, `cgroup` and `deny_udp` stay file-only in the action.
A job that needs them has a reason to ship a config file. Each input is
ignored with a warning unless `enforce` is `"true"`.

The runner binaries stay exempt automatically. The inputs add to that, as
they add to the file.

## Acceptance

Each row is an acceptance script in `test/acceptance/enforce/` and a
`catalog.yaml` entry.

| Guarantee | Check |
| --- | --- |
| Status names the config file | `pmg proxy status` prints the path and the `managed` or `root per-user` label. |
| Fallback warns | A root start without a managed file prints the warning and records it in the state file. |
| `--system` edits the managed file | `sudo pmg config set --system proxy.server.enforce.deny_udp false` changes `/etc/safedep/pmg/config.yml` and the next daemon reports `deny_udp: false`. |
| `--system` needs root | The same command without sudo fails with `PermissionDenied`. |
| sudo without `--system` refuses | `sudo pmg config edit` fails and names both files. |
| Flags add to the file | A file with one skip destination and a start with `--enforce-skip-destination` for another gives a status with both. |
| Lockdown governs widening flags | With `global_lockdown: true`, `--enforce-exempt-user` fails fast and `--enforce-port` is accepted. |
| Action inputs reach the daemon | The action e2e job passes `enforce-skip-destinations` and the status shows it. |

## Rollout

1. Part 1. Small and self-contained. Ships first.
2. Part 2 with `pmg config path`.
3. Part 3 with the env rows in `docs/config.md` and the lockdown rule.
4. Part 4 with the action e2e case.

## Decisions needed

- Add or replace for list flags. This spec says add, for the reason in
  part 3. Replace would need a separate `--enforce-no-file-policy` or a
  similar escape, which is one more thing to govern under lockdown.
- Whether `--system` under `global_lockdown` should also need an explicit
  `--unlock` acknowledgement. This spec says no: root is the administrator,
  and the file is already root-only on disk.
