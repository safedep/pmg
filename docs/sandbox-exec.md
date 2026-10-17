# Sandbox Exec

`pmg sandbox exec` runs any program inside the PMG sandbox. The program keeps its own stdin,
stdout, stderr and exit code. PMG blocks credential files, scrubs credential environment
variables, protects agent hook configuration and contains writes to the repository.

> `pmg sandbox exec` is experimental. SafeDep improves and hardens it actively, so its behavior
> and defaults can change between releases.

The first use is a coding agent. Claude Code, Codex and Pi run dozens of tool calls per session.
Under `pmg sandbox exec` every process the agent spawns runs under the same kernel policy.

```bash
pmg sandbox exec -- claude
pmg sandbox exec --sandbox-allow preset=codex -- codex
pmg sandbox exec -- make test
```

Flag parsing stops at the first non-flag argument, so the program's own flags pass through. Put
`--` before a program name that starts with a dash.

## What the exec profile enforces

The built-in `exec` profile is deliberately broad on read and exec. A coding agent reads the whole
toolchain and runs whatever the repository needs, so a narrow allow list only produces false
denials. The value is in the deny rules:

- Credential files are denied for read and write, anywhere in the repository and the home
  directory. The mandatory deny list in the sandbox source names them.
- `git add` and `git commit` work. Git hooks and the repository config are read-only.
- Credential environment variables are scrubbed, model API keys included.
- Writes land only in the repository, temp directories, tool caches and the state directories the
  presets add. System directories are read-only.
- Agent hook configuration is read-only. A hook runs an arbitrary command on every tool call, so a
  write there is code execution and a way to unhook an agent security layer such as
  [Gryph](https://github.com/safedep/gryph).

Every outbound connection goes through a PMG proxy, and the `exec` profile allows every
destination, because an agent needs its model API and the registries of every tool it runs. A
child profile or the network flags narrow it. See [Network](#network).

Unix sockets are blocked. An agent cannot reach the SSH agent or the Docker daemon, so `git push`
over SSH fails. Use an HTTPS remote, or a custom profile that sets `allow_unix_sockets: true`. See
[Unix Sockets](sandbox.md#unix-sockets).

Show the full profile with `pmg sandbox profile show exec`.

## Agent presets

A preset adds the footprint of one agent: its state directory and its own API key. Deny rules win
over a preset allow, so the hook configuration stays read-only.

The presets are `claude`, `codex` and `pi`. Each one grants the agent's state directory and
re-allows the agent's own API key. Read a preset with `pmg sandbox preset show claude`.

Apply a preset for one run, or save it for the current repository:

```bash
pmg sandbox exec --sandbox-allow preset=claude -- claude
pmg sandbox allow preset=claude && pmg sandbox exec -- claude
```

Each preset file states the residual risk of each allowance. Read it with
`pmg sandbox preset show claude`. The accepted trade-off is the same as `NPM_TOKEN` in the npm
profile: the agent's own key is visible to every process the agent spawns. An OAuth login does
not need the key at all.

## When something is denied

The program sees a plain permission error. Run `pmg sandbox explain --last` after the run to see
what was denied and the `pmg sandbox allow` command that opts out of it. Saved allowances live in
the per-repository overlay. See [sandbox.md](./sandbox.md#project-overlays).

A tool that must edit its own settings file while sandboxed needs an exact-match opt-out:

```bash
pmg sandbox allow write=$HOME/.claude/settings.json
```

## Custom profiles

A custom profile must list the `exec` workload:

```yaml
name: exec-tight
inherits: exec
package_managers: [exec]
presets: [claude]
filesystem:
  deny_write:
    - ${CWD}/infra/**
```

```bash
pmg sandbox exec --sandbox-profile exec-tight -- claude
```

Or map the workload to the profile in the PMG config:

```yaml
sandbox:
  policies:
    exec:
      enabled: true
      profile: exec-tight
```

`pmg sandbox exec` fails when the exec policy is missing or disabled. It never runs a program
without a sandbox. It turns the sandbox on for the run even when `sandbox.enabled` is false in the
config file.

## Network

`pmg sandbox exec` starts a proxy for the program and applies the `network` block of the
profile to every connection the proxy sees. The proxy has no interceptors and does not
terminate TLS. It reads no traffic. It decides each destination by host and port. See
[Network rules](sandbox.md#network-rules) for the rule syntax and `deny_ip_literals`.

The program gets the proxy through `HTTP_PROXY`, `HTTPS_PROXY`, their lower-case forms and
`NODE_USE_ENV_PROXY=1`. The `exec` profile also sets `network_via_proxy_only`, so the sandbox
driver refuses every outbound connection that does not go to the proxy. A program that ignores
the proxy variables fails to connect instead of going around the policy. Loopback stays open, so
a dev server the agent starts is reachable without the proxy.

```bash
pmg sandbox exec --network-mode enforce --network-deny '*:*' \
  --network-allow api.anthropic.com:443 --network-allow registry.npmjs.org:443 -- claude
```

| Config key | Flag | Variable |
| --- | --- | --- |
| `sandbox.network_mode` | `--network-mode` | `PMG_SANDBOX_NETWORK_MODE` |
| none | `--network-allow` (repeatable) | none |
| none | `--network-deny` (repeatable) | none |

The rule flags add one `host:port` rule each to the resolved profile. `--network-allow` also
removes an equal deny rule. Under `audit`, the default, the proxy records a match on a deny rule
and lets the connection through. Under `enforce` the proxy refuses the connection with a 403 that
names the destination and the rule. Under `global_lockdown`, pmg refuses `--network-allow`,
and refuses `--network-mode audit` over a config that says `enforce`. A deny rule and `enforce`
over `audit` narrow the policy and pass.

A clean run writes nothing. When a deny rule matched, the run writes the report to stderr after
the program exits. Stdout holds only the program's output:

```text
⊘ Network policy denied 1 destination(s):
    pastebin.com:443  rule *:*
  Allow one for this run with --sandbox-allow net-connect=<host>:<port>, or keep it with pmg sandbox allow net-connect=<host>:<port>.

  Network: 4 destination(s) observed. Propose a profile with: pmg sandbox profile propose --run 3f9c2a1b7d4e
```

Every run writes a `network_observation` event, so a run in `audit` builds the allow list. Run
the agent once, then `pmg sandbox profile propose --last --new agent.yml`. The profile inherits
`exec`, has one allow rule per destination, `deny_ip_literals: true` and the catch-all deny. Run
the agent under it with `--sandbox-profile agent.yml --network-mode enforce`. A refused
destination shows in `pmg sandbox explain --last`, and `pmg sandbox allow net-connect=<host>:<port>`
keeps it for the repository.

### How the policy reaches the program

Landlock and Seatbelt apply `network_via_proxy_only`. Bubblewrap does not, and refuses the `exec`
profile, so `pmg sandbox exec` needs one of the other two drivers. `pmg sandbox doctor` says
which in the `Exec network path` row.

The `exec` profile sets `allow_network_bind`, so the drivers keep loopback open and `NO_PROXY`
sends it around the proxy. A local service the program reaches is outside the policy. Direct DNS
is refused under confinement. A client behind a proxy does not resolve names itself, so this is
invisible to an HTTP client. A tool that resolves a name and then connects direct fails on the
resolve.

A child profile may set `network_via_proxy_only: false`. The program then gets the proxy by
environment only, a program that ignores the variables goes around the policy, and the report
under `enforce` says so.

A proxy connection has a wall-clock limit of 24 hours. A long agent session keeps its model API
connection. A program that pins the model API by address needs an exact address rule when the
profile sets `deny_ip_literals`.

## Package managers inside the sandbox

PMG strips its own shim directories from the child's `PATH`. An `npm install` the agent runs
inside `pmg sandbox exec` reaches the real npm, not the PMG proxy. Malware analysis and dependency
cooldown do not apply to it. The sandbox still applies.

A future version may keep the shim on `PATH` and instead disable the PMG-in-PMG guard with an
environment variable, so an `npm install` inside `pmg sandbox exec` keeps malware analysis and
cooldown.

## Git worktrees

In a linked worktree or a submodule, `.git` is a file that points at a directory outside the
checkout. PMG repeats every `.git` rule of the profile for that directory and for the main
checkout's `.git`, so `git commit` works, while `hooks` and `config` there stay denied like they
do under the working directory.

The pointer files are repository content, so PMG trusts them only when the git directory names
this checkout as its worktree, the way git wrote it. A `.git` file that points at the home
directory or at another repository grants nothing. The `.git` file and the `gitdir` and
`commondir` files of the worktree are read-only inside the sandbox, so `git worktree move` and
`git worktree repair` fail there.

## Limits

- Windows is not supported. The sandbox drivers are macOS Seatbelt and Linux Landlock or
  Bubblewrap. On Linux, only amd64 and arm64 are supported.
- Under Bubblewrap, a script without a `#!` line fails with "exec format error". Add a `#!`
  line, or run it with its interpreter, as in `pmg sandbox exec -- sh ./script`.
- Bubblewrap cannot confine outbound connections to the proxy, so it refuses the `exec`
  profile. See [How the policy reaches the program](#how-the-policy-reaches-the-program).
- `git worktree add` and `git worktree remove` are not supported yet. A new worktree lands
  outside the working directory, which the profile does not grant. This is future work.
- The exec profile grants exec access under `${HOME}`. `pmg sandbox profile lint exec` reports
  this as a warning on purpose.
- A hard link to a credential file that exists before the run is a second name for the same
  inode. Landlock and Bubblewrap check names, so a read through that name succeeds. A hard link
  made inside the sandbox is refused.
- Bubblewrap works with mounts, so it denies only paths it can name. It hides credential files
  in the repository up to three levels deep. Landlock and Seatbelt deny them at any depth. A
  denied file that does not exist yet, such as `~/.codex/hooks.json` before Codex creates it,
  can be created under Bubblewrap when its parent is writable. A denied directory that does
  not exist yet, such as `~/.claude/hooks`, gets an empty read-only placeholder that stays on
  the host after the run.
