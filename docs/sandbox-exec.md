# Sandbox Exec

`pmg sandbox exec` runs any program inside the PMG sandbox. The program keeps its own stdin,
stdout, stderr and exit code in direct mode.
With terminal stdin and stdout, PMG uses a PTY.
The child's stderr then shares PMG's stdout stream, so `2>` does not capture it.
PMG applies credential denies, environment scrubbing, and write restrictions with the limits below.

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

- The mandatory credential list covers `.env`, `.ssh`, `.aws`, and the other [listed paths](sandbox.md#security-model).
  Driver path-matching limits still apply.
  Other token files, including `~/.npmrc`, `~/.pypirc`, and `~/.cargo/credentials.toml`, remain readable unless a child profile denies them.
- Unsigned `git add` and `git commit` can work.
  `.git/hooks` is denied for read and write, so Git cannot execute those hooks inside the sandbox.
  `.git/config` is read-only.
  A `core.hooksPath` inside the writable checkout stays writable.
  A planted hook can run on a later unsandboxed commit.
  GPG and SSH signed commits fail when their credential directories or agent sockets are blocked.
- Credential environment variables are scrubbed, model API keys included.
- Writes land only in the repository, temp directories, tool caches and the state directories the
  presets add, plus the Gryph event database. System directories are read-only.
- The explicit user hook files in [exec.yml](../sandbox/profiles/exec.yml) have write denies.
  Claude Code's project settings and hooks also have denies.
  Other project hook files remain writable under the checkout grant.
  Examples include `.cursor/hooks.json`, `.codex/hooks.json`, and `.codex/config.toml`.
  The Codex preset also leaves `~/.codex/config.toml` writable, including inline hooks.
  A hook write can install future command execution or disable a security layer such as [Gryph](https://github.com/safedep/gryph).

PMG routes proxy-aware clients through its proxy.
The `exec` profile allows every proxy destination so an agent can reach model APIs and package registries.
A child profile or the network flags can narrow these proxy rules.
Direct network restrictions have limits, including open loopback connections.
See [Network](#network).

Unix sockets are blocked. An agent cannot reach the SSH agent or the Docker daemon, so `git push`
over SSH fails.
Use an HTTPS remote with a credential source the sandbox permits.
The macOS keychain helper can supply stored credentials.
On Linux, common credential files, gh state, credential-cache sockets, and libsecret sockets are blocked.
`GH_TOKEN` and `GITHUB_TOKEN` are scrubbed.
Enabling Unix sockets alone does not fix SSH because direct TCP and SSH files remain blocked.
It can expose services such as Docker.
See
[Unix Sockets](sandbox.md#unix-sockets).

Show the full profile with `pmg sandbox profile show exec`.

## Agent presets

A preset adds the footprint of one agent: its state directory, its own API key and the hosts it
reaches.
Read the [preset precedence limits](sandbox-presets.md).
Preset network rules can beat a catch-all deny and some partially overlapping port-specific denies.
Hook protection is limited to the explicit paths above.

The presets are `claude`, `codex` and `pi`. Each one grants the agent's state directory,
re-allows the agent's own API key, and allows the agent's own hosts: its model API, its sign-in,
its update check and its telemetry. The preset file names the source of each host and says how
to drop the optional ones. The `exec` profile allows every destination. The hosts matter under a
profile that denies `*:*`, which `pmg sandbox profile propose` writes. The preset opens the
agent's hosts. The profile keeps the hosts the repository needs. Read a preset with
`pmg sandbox preset show claude`.

Apply a preset for one run, or save it for the current repository.
Save it only when you accept those allowances for every later sandboxed workload, including package install scripts.

```bash
pmg sandbox exec --sandbox-allow preset=claude -- claude
pmg sandbox allow preset=claude && pmg sandbox exec -- claude
pmg sandbox exec --sandbox-profile agent --network-mode enforce --sandbox-allow preset=claude -- claude
```

Use `pmg sandbox project reset` to remove saved allowances.
To customize a preset, give the copy a new name under `<config-dir>/sandbox/presets/` and use `preset=<new-name>`.
A same-name copy is shadowed by the built-in.
See [preset authoring](sandbox-presets.md#creating-your-own-preset).

Each preset file states the residual risk of each allowance. Read it with
`pmg sandbox preset show claude`. The accepted trade-off is the same as `NPM_TOKEN` in the npm
profile: the agent's own key is visible to every process the agent spawns. An OAuth login does
not need the key at all.

## When something is denied

The program sees a plain permission error. Run `pmg sandbox explain --last` after the run to see
what was recorded and a suggested allowance command.
Review that suggestion before applying it. Saved allowances live in
the per-repository overlay. See [sandbox.md](./sandbox.md#project-overlays).

A tool that must edit its own settings file while sandboxed needs an exact-match opt-out:

```bash
pmg sandbox exec --sandbox-allow "write=$HOME/.claude/settings.json" -- claude
```

The saved form, `pmg sandbox allow write=...`, permits every later sandboxed workload here to rewrite the agent's hooks.
It does not require `--force` for this settings file.
Prefer the one-run opt-out.

The exec cache grants can include PMG's violation JSON and persistent analysis database.
A sandboxed process can forge reports or alter later cached verdicts when disk analysis caching is enabled.
`pmg setup cache clear` clears disk analysis verdicts in the current identity's cache.
Stop a daemon first to discard its memory verdicts too.
Clearing verdicts does not authenticate violation reports or stop a live writer.
See [cache security](caching.md).

Default PMG configuration and sandbox directories have explicit write denies.
These denies do not follow `PMG_CONFIG_DIR`.
Keep relocated policy state outside all writable grants, or add explicit write denies for it.
A config directory under the checkout or temp grant can let the child change later profiles and overlays.

## Custom profiles

A custom profile must apply to `exec` through inheritance or `package_managers`.
Create a discoverable user profile before running it.

```sh
pmg sandbox profile init exec-tight --from exec --package-manager exec
```

Edit `<config-dir>/sandbox/profiles/exec-tight.yml` to add the following rules.
The default exec denies protect that user profile directory.

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

`pmg sandbox exec` fails when the exec policy is missing or disabled unless `--sandbox-profile` selects a profile. It never runs a program
without a sandbox. It turns the sandbox on for the run even when `sandbox.enabled` is false in the
config file.

Under [managed lockdown](config.md#lockdown), user presets and overlays do not apply.
PMG refuses runtime profile and sandbox-allow overrides and saved allowance commands.
An administrator must create the profile file, register its path under `sandbox.policy_templates`, and map `sandbox.policies.exec` to that template.
A template value is a file path, not inline profile YAML.

## Network

`pmg sandbox exec` starts a proxy for the program and applies the `network` block of the
profile to every connection the proxy sees. The proxy has no interceptors and does not
terminate TLS. It reads no traffic. It decides each destination by host and port. See
[Network rules](sandbox.md#network-rules) for the rule syntax and `deny_ip_literals`.

The program gets the proxy through `HTTP_PROXY`, `HTTPS_PROXY`, their lower-case forms and
`NODE_USE_ENV_PROXY=1`. The `exec` profile also sets `network_via_proxy_only`, so the sandbox
driver restricts direct outbound connections.
Clients that ignore the proxy generally fail on their direct remote connection.
Examples include database clients such as `psql` and `mysql`, `ssh` and git over ssh,
and raw TCP tools such as `nc`.
Loopback remains open because the profile enables `allow_network_bind`.
Remote direct DNS is refused, but a loopback resolver such as `127.0.0.53:53` can still answer and forward queries off-host.
This remains a DNS exfiltration path.
Linux Landlock also does not inspect `sendmmsg`, and a racing thread can change a destination after the supervisor check.
See [network lockdown gaps](sandbox-landlock.md#network-lockdown-gaps).
A child profile with `network_via_proxy_only: false` keeps only advisory environment routing.

Node's built-in environment proxy support depends on the release line.
For built-in `fetch`, use Node 22.21+ in the 22 line or Node 24.0+.
For `node:http` and `node:https`, use Node 22.21+ in the 22 line or Node 24.5+.
Other clients can use their own proxy implementation independently.
See [Node network configuration](https://nodejs.org/learn/http/enterprise-network-configuration).

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
removes an equal deny rule. The matcher treats a flag rule like a profile rule, so the more
specific rule wins. A preset rule fully covered by one non-catch-all flag deny is dropped, and a saved allow does not
remove a flag deny. Under `audit`, the default, the proxy records a match on a deny rule
and lets the connection through. Under `enforce` the proxy refuses the connection with a 403 that
names the destination and the rule. Under `global_lockdown`, pmg refuses `--network-allow`,
and refuses `--network-mode audit` over a config that says `enforce`. A deny rule and `enforce`
over `audit` narrow the policy and pass.

A clean run writes nothing. When a deny rule matched, the run writes a short report to stderr
after the program exits. One refused destination takes two lines. Several get a header and one
row each. Stdout holds only the program's output:

```text
⊘ Network policy denied pastebin.com:443  rule *:*
  Allow it with pmg sandbox allow net-connect=pastebin.com:443.
```

Under `--verbose` the report also names the one-run override, `--sandbox-allow
net-connect=<host>:<port>`, and a run with an observed destination and event-log run ID ends with a dim proposal line.

```text
  Network: 4 destination(s) observed. Propose a profile with: pmg sandbox profile propose --run 3f9c2a1b7d4e
```

A run that observes a destination writes a `network_observation` event when event logging is enabled.
Run the agent once, then `pmg sandbox profile propose --last --new agent`.
The bare name writes into the user profile directory.
A path such as `agent.yml` writes into the checkout, where the sandboxed program can edit it and weaken its next run. The profile inherits
`exec`, has one allow rule per destination, `deny_ip_literals: true` and the catch-all deny. Run
the agent under it with `--sandbox-profile agent --network-mode enforce`. A refused
destination shows in `pmg sandbox explain --last`, and `pmg sandbox allow net-connect=<host>:<port>`
keeps it for the repository.

### How the policy reaches the program

Landlock and Seatbelt apply `network_via_proxy_only`. Bubblewrap does not, and refuses the `exec`
profile.
For Bubblewrap, create a child profile with `network_via_proxy_only: false`.
That workaround loses direct outbound confinement. `pmg sandbox doctor` says
which in the `Exec network path` row.

The `exec` profile sets `allow_network_bind`, so the drivers keep loopback open and `NO_PROXY`
sends it around the proxy.
Local services are outside the proxy network policy.
A local resolver can also forward DNS queries off-host.
A tool that resolves locally and then connects remotely can fail at the connect instead of the lookup.

A child profile may set `network_via_proxy_only: false`. The program then gets the proxy by
environment only, a program that ignores the variables goes around the policy, and the report
under `enforce` says so.

A proxy connection has a wall-clock limit of 24 hours. A long agent session keeps its model API
connection. A program that pins the model API by address needs an exact address rule when the
profile sets `deny_ip_literals`.

## Package managers inside the sandbox

PMG strips its own shim directories from the child's `PATH`. An `npm install` the agent runs
inside `pmg sandbox exec` reaches the real npm, not the PMG proxy. Malware analysis and dependency
cooldown do not apply on that direct path. The sandbox still applies.
PMG does not remove shell aliases installed by setup.
A child shell that loads those aliases can still resolve npm to `pmg npm` inside the sandbox.

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
- On Linux, Landlock and Bubblewrap both use raw execution, so a script without a `#!` line fails with "exec format error". Add a `#!`
  line, or run it with its interpreter, as in `pmg sandbox exec -- sh ./script`.
- Bubblewrap cannot confine outbound connections to the proxy, so it refuses the `exec`
  profile. Use a child with `network_via_proxy_only: false`.
  The Bubblewrap path limits below apply to that workaround. See [How the policy reaches the program](#how-the-policy-reaches-the-program).
- `git worktree add` and `git worktree remove` are not supported yet. A new worktree lands
  outside the working directory, which the profile does not grant. This is future work.
- The exec profile grants exec access under `${HOME}`. `pmg sandbox profile lint exec` reports
  this as a warning on purpose.
- A hard link to a credential file that exists before the run is a second name for the same
  inode. Landlock and Bubblewrap check names, so a read through that name succeeds. A hard link
  made inside the sandbox is refused.
- Bubblewrap works with mounts, so it denies only paths it can name. It hides credential files
  in the repository up to three levels deep.
  Landlock and Seatbelt have different [recursive deny limits](sandbox.md#security-model). A
  denied file that does not exist yet, such as `~/.codex/hooks.json` before Codex creates it,
  can be created under Bubblewrap when its parent is writable. A denied directory that does
  not exist yet, such as `~/.claude/hooks`, gets an empty read-only placeholder that stays on
  the host after the run.
