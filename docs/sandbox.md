# Sandbox

PMG sandbox design goal is to protect against unknown supply chain attacks using principle of least privilege.

We do not want to re-invent sandbox and rely on OS native sandbox primitives. This is at the cost of
developer experience, where we have to work within the limitations of the sandbox implementations
that we use.

## Security Model

Filesystem access is default-deny, with driver-specific implicit grants.
Filesystem denies take precedence over allows where the driver can express them.
Environment allows win over denies.
Network rules use specificity and allow unmatched destinations.
Process `allow_exec` is additive, not a portable exclusive allow-list.
Seatbelt permits execution generally and applies `deny_exec`.
Bubblewrap ignores `allow_exec` and masks named, existing denied binaries.
Landlock grants execution through filesystem access and implicit system rules as well as `allow_exec`.
A narrow Landlock filesystem policy can still restrict other execution.
A denied executable path does not cover every copy or execution through an allowed loader.

PMG ships mandatory denies for credential files (`.env`, `.ssh`, `.aws`, `.gcloud` and more). It also denies writes to the project-root directories whose
contents execute outside the sandbox (`.github/workflows`, `.vscode`). See
[dangerous.go](../sandbox/util/dangerous.go) for the full list.
Other future execution surfaces such as `.claude`, `.cursor`, `.devcontainer`, `.idea`, and `.husky` remain writable in ordinary package-manager profiles.
To allow legitimate access, you can opt out of a mandatory deny
via an exact match entry in `allow_read` or `allow_write` (in the policy or via `--sandbox-allow`).
Driver limitations below qualify credential protection.

<details>
<summary>Detailed rules</summary>

- **Filesystem default deny.** A resolved policy needs at least one package manager and one access rule.
  PMG refuses an empty policy.
- **Deny rules override allow rules**: When a path appears in both allow and deny lists, the deny rule wins. Deny rules are placed after allow rules in the generated sandbox profile to ensure this.
- **Credential and sensitive file protection**: The sandbox blocks read and write access to known list of credential files by default.
- **Git hooks are always blocked**: Read and write access to `.git/hooks/` in both `$CWD` and `$HOME` is always denied to prevent arbitrary code execution via repository hooks. A repository that sets `core.hooksPath` to a directory inside the working tree (for example, husky sets `.husky/_`) is not covered. That directory is writable under the default profiles. Git does not read `.git/hooks` there. The `.git/config` deny stops a package from setting `core.hooksPath` itself.
- **Git config is blocked by default.** Read and write access is denied unless `allow_git_config: true` changes it.
  To enable only reads, add an exact `${CWD}/.git/config` read allowance or use the `git` preset.
  The exec profile already has that read allowance.
- **The project directory is writable by default**: The built-in package manager profiles allow writes to `${CWD}` and `${CWD}/**` so install scripts and build output work without per-path allowances. Mandatory denies still block credential files inside the project, and writes to `.git`, `.github/workflows` and `.vscode` at the project root. The whole `.git` directory is write-denied unless `allow_git_config: true` is set, because hooks and config also live under `.git/modules` and `.git/worktrees`. The `git` preset opts out with an exact `${CWD}/.git` entry while top-level hooks and config retain separate denies.
  Submodule hooks and config under `.git/modules` can become writable with this opt-out.
- **Runtime overrides remove only exact-match deny entries**: When `--sandbox-allow` adds a path to an allow list, PMG removes equal entries after path expansion.
  An identical glob override can remove a glob deny such as `/etc/**`.
  A narrower path cannot remove a broader glob deny. An exact-match entry in `allow_read` or `allow_write` (policy or runtime) opts out of the mandatory deny for that credential file. `.git/hooks` does not accept opt-outs.
- **Profile inheritance is a chain**: A profile inherits from one parent, and the parent can inherit in turn. A built-in profile inherits only from a built-in. A custom profile inherits from a built-in profile, a policy template (by name), a user profile (by name) or a file path, in that order. A relative path is read from the directory of the file that names it. A built-in name wins over a template of the same name, so a template that overrides a built-in is reached only through `policies.<pm>.profile`. Lists merge by union from the base down. A child without `package_managers` takes them from its parent. Boolean fields (`allow_pty`, `allow_git_config`, `allow_unix_sockets`, `allow_network_bind`, `network_via_proxy_only`, `allow_direct_dns`, and `network.deny_ip_literals`) in the child override the parent. A chain that loops is an error. `pmg sandbox profile show <name> --resolved --json` prints the chain as `lineage`.
- **Variable expansion is runtime-only**: Policy paths use `${HOME}`, `${CWD}`, `${TMPDIR}` and the XDG Base Directory variables `${XDG_CACHE_HOME}`, `${XDG_CONFIG_HOME}`, `${XDG_DATA_HOME}` and `${XDG_STATE_HOME}`. PMG expands them when it sets up the sandbox, not when it reads the policy. An XDG variable expands to its value in the environment, or to its default below `$HOME` (see the table below). Presets cannot use the XDG variables.

  | Variable | Default |
  | --- | --- |
  | `${XDG_CACHE_HOME}` | `$HOME/.cache` |
  | `${XDG_CONFIG_HOME}` | `$HOME/.config` |
  | `${XDG_DATA_HOME}` | `$HOME/.local/share` |
  | `${XDG_STATE_HOME}` | `$HOME/.local/state` |

  Each variable takes its default when its value is unset, empty or relative. It also takes its default, with a diagnostic warning visible through `--debug` or `--log <file>`, when its value is `/`, `$HOME`, a parent of `$HOME` or a glob pattern. Under `global_lockdown`, each variable always takes its default.

  The XDG spec treats an empty or relative value as unset, so the package manager also uses the default, and the rule matches its path. For `/`, `$HOME`, a parent of `$HOME` and a glob, PMG expands its rule to the default, but the package manager itself still writes to the value. The sandbox denies those writes, and the warning names the variable.
- **Unix sockets are blocked by default**: A sandboxed process cannot connect to a host unix socket, such as the SSH agent (`SSH_AUTH_SOCK`) or the Docker daemon. Set `allow_unix_sockets: true` in a profile to open them. See [Unix Sockets](#unix-sockets).
- **Dangerous syscalls are blocked on Linux**: The kernel refuses nested namespaces, ptrace, `bpf`, `io_uring`, mounts, kernel modules and a few more on both Linux drivers. See [sandbox-landlock.md](sandbox-landlock.md).
- **Process-level isolation only**: The sandbox restricts the package manager process and its children. It does not enforce CPU, memory, or disk quotas. The drivers can turn the network on or off, or restrict direct outbound traffic with `network_via_proxy_only`, subject to their limits. The PMG proxy applies the host and port rules, see [Network rules](#network-rules).

</details>

### Mandatory Credential Protection

PMG maintains a known list of credential and sensitive files at
[dangerous.go](../sandbox/util/dangerous.go) that are blocked by default in the sandbox. PMG injects three deny patterns per file:

- The path under `${CWD}`
- The path under `${HOME}`
- A `**/<file>` glob.
  Landlock matches the name and its descendants at any depth.
  Seatbelt matches nested file names such as `.env`, but its nested directory regex stops at the directory name.
  A file inside `sub/.aws` can therefore remain readable on macOS.
  The separate HOME and CWD anchored directory forms still protect their subtrees.
  Bubblewrap masks existing matches under CWD to depth 3, with at most 200000 scanned entries.
  Deeper and later-created matches can remain uncovered.

To opt out, list the literal path in `allow_read` or `allow_write` in your policy, or pass
`--sandbox-allow read=...` / `write=...` at runtime. Listing a CWD-absolute or HOME-absolute path
also suppresses the matching `**/<file>` glob on the same direction, so `--sandbox-allow
read=./.env` is enough to read `${CWD}/.env`. Suppression needs an exact match after expansion. A
broad glob such as `${HOME}/**` does not opt out of `${HOME}/.aws`. The unnamed absolute form stays denied.
`.git/hooks` does not accept opt-outs because hooks can execute arbitrary code.

### Environment Variable Protection

Many supply chain attacks steal credentials from the **process environment** rather than from files
(e.g. `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`, `TWINE_PASSWORD`). When the sandbox is
enabled, PMG scrubs a default-deny list of credential-bearing variables from the package manager
child process before it is spawned. The built-in list is an explicit, curated set of **known** secret
names. See [`DANGEROUS_ENV_VARS`](../sandbox/util/dangerous.go). There are deliberately no generic
`*_TOKEN` / `*_SECRET` catch-alls in the default, because broad wildcards there would risk clipping
legitimate build variables.

Scrubbing is platform-independent (it filters the environment regardless of the OS sandbox driver)
and runs as the last step before launch, after project overlays and `--sandbox-allow` overrides are
merged. Scrubbed variable **names** (never values) are logged at info level. Run with `--debug` to
see what was removed.

When a sandboxed command fails, or when a clean run records a denial, the scrubbed names are also
recorded to the violation cache as `env_scrub` violations, so `pmg sandbox violations list` and
`pmg sandbox explain --last` can name them after the run. After a failed run, text `explain` suggests `--sandbox-allow env=NAME` only when that scrub is the primary violation and its name permits a suggestion.
`explain --json` gives per-variable saved commands in `env_remediations`.
`pmg sandbox allow --last` saves only the primary violation.
Another filesystem, execution, or network denial can outrank the scrub.
`--last --all` includes other safe denials too and can require `--force` for a secret name. PMG records only the names. The values never reach the cache.

A variable whose value is a secret gets no suggestion to save it. PMG treats a name as secret
when one of its underscore-separated segments is `SECRET`, `TOKEN`, `KEY`, `APIKEY`,
`PASSWORD`, `PASSWD` or `AUTH`. PMG also treats `GOOGLE_CREDENTIALS` as secret, since it can
hold the service account key inline. `pmg sandbox allow` refuses such a name without `--force`.
A name that only points at a credential file, such as `GOOGLE_APPLICATION_CREDENTIALS`, keeps
the normal suggestion. The sandbox still controls access to the file.

The shared base profiles (`npm-restrictive`, `pypi-restrictive`) allow no environment variables.
Each package manager's leaf profile (`npm`, `yarn`, `bun`, `pnpm`, `aube`, `npx`, `pnpx`, `aubx`, `pip`,
`pipx`, `uv`, `uvx`, `poetry`) re-allows only the variables that package manager legitimately needs via an
`environment.allow` block, so package managers keep working:

```yaml
environment:
  # Re-permit only what this package manager needs; everything else in the
  # default deny list stays scrubbed. allow always wins over deny.
  allow:
    - NPM_TOKEN
    - npm_config_*
  # Optionally scrub more than the default. Glob patterns are supported here
  # (the built-in list has no generic catch-all, but includes `CARGO_REGISTRIES_*_TOKEN`).
  deny:
    - MY_CUSTOM_SECRET
    - "*_TOKEN"
```

**Accepted trade-off.** Every JavaScript leaf profile re-allows npm tokens such as `NPM_TOKEN`, `NPM_AUTH_TOKEN`, and `NODE_AUTH_TOKEN`.
Yarn and Bun also need their own variables.
An install script under any of these profiles can read the permitted npm credentials.
Python leaf profiles preserve their tool-specific allowances.
`pnpx` inherits its environment allowances from `npx`.
The Go, Cargo, and exec profiles do not add credential environment allowances by default.

Configs written before the profile split may still map npm, yarn, or bun to `npm-restrictive`, pnpm
to `pnpm-restrictive`, or pip, pip3, pipx, poetry, or uv to `pypi-restrictive`. PMG re-maps these legacy
defaults to the per-package-manager leaf profile at load time, unless a custom policy template
overrides the legacy name, in which case the template wins as before.
PMG also re-maps the old pnpx-to-npx mapping to the pnpx leaf profile.

Matching is on the variable name, case-insensitive, and supports the same glob syntax as filesystem
rules. A small set of core variables (`PATH`, `HOME`, `LC_*`, `TZ`, ...) is never scrubbed.

### Unix Sockets

A host unix socket reaches a service outside the sandbox. The SSH agent signs as you, and the
Docker daemon gives root. So every built-in profile blocks unix socket connections:

- Linux: the kernel refuses `socket(AF_UNIX)`. It allows `socketpair` only for stream and
  seqpacket pairs, which runtimes use for child stdio.
- macOS: Seatbelt denies outbound connections to unix sockets. The mDNSResponder socket stays
  open so DNS works outside proxy-only confinement.
  Under `network_via_proxy_only`, it opens only with `allow_direct_dns: true`.

Tools that need a socket fail. Examples are `git` over SSH, `git+ssh` dependencies and the Docker
CLI. Use HTTPS remotes, or a custom profile that sets `allow_unix_sockets: true`. A preset cannot
set it. With `network_via_proxy_only`, `allow_unix_sockets` lets traffic go around the proxy
through a host socket, and `pmg sandbox profile lint` warns about it.

On Ubuntu 23.10 and later, AppArmor also refuses a connect to a host socket from the Landlock
driver's user namespace, even with `allow_unix_sockets: true`. Install the pmg AppArmor profile
described in [AppArmor blocks the Landlock driver](#apparmor-blocks-the-landlock-driver-ubuntu-2310)
to lift that restriction for pmg.

## Requirements

- Linux kernel 5.13+ with Landlock enabled (default, no external dependencies)
- Bubblewrap on Linux (fallback for kernels < 5.13, or when `PMG_SANDBOX_DRIVER=bubblewrap` is set)
- Seatbelt on macOS
- Linux amd64 or arm64 with user namespaces available for a non-root caller. Both Linux drivers need them.
  A runtime namespace clone failure stops the run and does not trigger driver fallback.
- On Ubuntu 23.10+, an AppArmor profile granting pmg unprivileged user namespaces. See
  [AppArmor blocks the Landlock driver](#apparmor-blocks-the-landlock-driver-ubuntu-2310)

<details>
<summary>Bubblewrap Installation on Linux</summary>

For Debian-based Linux distributions, you can install Bubblewrap with the following command:

```bash
sudo apt install bubblewrap
```

For Arch Linux, you can install Bubblewrap with the following command:

```bash
sudo pacman -S bubblewrap
```

For other Linux distributions, you can install Bubblewrap from the package manager of your choice.
See [Bubblewrap Installation](https://github.com/containers/bubblewrap#installation) for more details.

</details>

## Usage

- Make sure sandbox is enabled in your `config.yml` file. See [configuration](./config.md) for the configuration schema.
- Make sure sandbox profiles are configured for the package managers you want to sandbox.
  
See [configuration](./config.md) and [config/config.template.yml](../config/config.template.yml) for the configuration schema.
Once sandbox is enabled, it covers commands that may download packages.
Known non-download commands can bypass sandboxing.
For npm, this includes `ls`, `uninstall`, `rebuild`, and `pack`, even though some can run package code.
Unknown subcommands and `npm run dev` remain sandboxed.
Set `sandbox.enforce_always: true` or add `--sandbox-enforce` to include all commands.
`--sandbox-enforce` alone does not enable the sandbox.

Run `pmg sandbox doctor` to see platform specific sandbox setup and driver status. Continue using
PMG as usual, sandbox will be applied to configured package managers automatically.

```bash
pmg npm install express
```

Explicitly enable sandbox if not enabled in the `config.yml` file:

```bash
pmg --sandbox npm install express
```

Run sandbox with custom policy file:

```bash
pmg --sandbox --sandbox-profile=/path/to/custom-policy.yml npm install express
```

On Linux, a profile can grant a store or cache under `${HOME}` only when that rule path exists. On a first run the package manager has not created it yet, so the sandboxed command
fails when it tries to. Run the package manager once outside the sandbox, or create the
directories by hand.
Starting with v0.34.0-edge.1, macOS Seatbelt can permit creating missing ancestors for these write grants.
Earlier macOS versions need the mkdir step too. For aube:

```bash
mkdir -p ~/.local/share/aube ~/.cache/aube
```

The aube profile uses these default paths. `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `AUBE_STORE_DIR` and
`AUBE_CACHE_DIR` move them, and the profile then denies the new location. Add the new paths
with `--sandbox-allow write=...` or a project overlay.

### Run any program in the sandbox

`pmg sandbox exec -- <command>` runs a program, such as a coding agent, under the built-in
`exec` profile. See [sandbox-exec.md](./sandbox-exec.md).

```bash
pmg sandbox exec -- claude
pmg sandbox exec --sandbox-allow preset=codex -- codex
```

### Sandbox Profile Commands

Use profile commands to inspect, create, and validate sandbox profiles.

```bash
# List built-in and user profiles
pmg sandbox profile list

# Scaffold a user profile that inherits from a built-in
pmg sandbox profile init my-npm --from npm --package-manager npm

# Open a user profile in $VISUAL / $EDITOR, then validate and lint it
pmg sandbox profile edit my-npm

# Show a profile, or its fully resolved policy
pmg sandbox profile show npm-restrictive
pmg sandbox profile show npm-restrictive --resolved

# Lint a built-in, user profile, or profile file
pmg sandbox profile lint npm-restrictive
pmg sandbox profile lint ./my-profile.yml --strict

# Compare two resolved profiles
pmg sandbox profile diff npm-restrictive pypi-restrictive

# Propose network rules from the destinations of the last run
pmg sandbox profile propose --last --new my-npm-network
```

`pmg sandbox profile edit` resolves the profile name to its file under the user profile
directory, opens it in your editor, and re-validates and lints the result when the editor
exits. Built-in profiles are embedded in the binary, so you cannot edit them. To get an editable
child profile, run `pmg sandbox profile init <new-name> --from <builtin> --package-manager <pm>`.
The scaffold inherits the base rather than copying it.
Its unioned lists cannot remove inherited entries.

To activate a user profile for a package manager, reference it by name in `config.yml` — no
policy template is needed for profiles in the user profile directory:

```yaml
sandbox:
  policies:
    pnpm:
      enabled: true
      profile: my-pnpm
```

Templates are needed to override a built-in name through the config mapping.
A mapping can also name an absolute or config-relative profile path directly.
A same-name user profile does not replace a built-in during registry lookup.
`profile list` can mark it shadowed.
Outside lockdown, a missing relative or bare reference can fall back to a same-named CWD file.
Repository content can then supply security policy.
Use an existing registered profile or an absolute existing path in an untrusted checkout.
Managed lockdown does not fall back to CWD.
See [configuration](config.md#lockdown).

### Sandbox Debug Commands

Use these commands when a sandboxed package manager command fails and you need to inspect why.

```bash
# Check sandbox driver availability and host setup
pmg sandbox doctor

# List recent sandbox denials captured by PMG
pmg sandbox violations list

# Explain the latest captured denial and show a suggested override when possible
pmg sandbox explain --last

# Inspect the resolved policy PMG will apply
pmg sandbox profile show npm --resolved
```

`pmg sandbox doctor` runs platform-specific checks for the current host. It checks the driver that
PMG uses, so a driver that PMG does not use cannot fail it. Add `--driver` to check another driver.
When no driver is available, it runs every check.

Cached violation reports used by `violations list` and `explain --last` are produced by macOS
Seatbelt diagnostics and, on Linux, by the Landlock driver's seccomp supervisor or the Bubblewrap
driver's reader of the sandboxed command's output.
The proxy also records connections refused under `network_mode: enforce`.

PMG records violations after every sandboxed run, also when the command exits 0. A program can
catch a denial and still exit 0. `violations list` and `explain` show the report of a clean run,
but it never becomes an override suggestion, and
`pmg sandbox allow --last` will not persist it. The command did not fail, so nothing needs an
allowance, and a program that catches a denial can be an attack.

Coverage differs by platform.

**macOS (Seatbelt).** PMG reads the denials from the unified log. After a failed run, it records
every denial. After a clean run, it does not record the noise that ordinary tools make on every
start. These are denials with no path, such as sysctl reads, and access to `/dev/dtracehelper` and
the terminal. `explain` ranks the same denials last. PMG records every other denial, also a write
that only the allow-list boundary blocks, such as a write to a shell startup file.

**Linux (Landlock).** The seccomp supervisor reports denied reads, writes, delete or rename operations, denied executables, and proxy-only `network_connect` operations.
The Landlock LSM itself does not report operations outside the allow-list or other kernel-only denials.
Operational events such as namespace fallback are excluded from violation reports.

**Linux (Bubblewrap).** The driver reports the denials that it recognises in the command's own
error output. Its platform section below says what that covers.

The executor scrubs environment variables before launch, independently of the driver.
It records scrubbed names after a failed run or a run with captured denials.
A clean run with only scrubs does not create that report.

PMG retains the 10 most recent local violation reports.
Sandbox-denial audit events can contain driver, profile, `clean_exit`, denied path, executable or host, rule, process, and count.
Cloud delivery can include up to 100 denial entries, with a byte budget that can reduce the list further.
Environment scrubs and diagnostic noise are filtered from that cloud denial payload.
Review this local-path data flow before enabling cloud sync.

### Runtime Allow Overrides

Use `--sandbox-allow` to make one-off exceptions without creating a custom profile. This is useful
when a command needs access that the default profile blocks.
Enable sandboxing through configuration or `--sandbox` before using these overrides.

```bash
# Allow writing to a specific file
pmg --sandbox-allow "write=$HOME/.example-tool-cache/**" npx create-next-app@latest

# Allow executing a binary blocked by the profile
pmg --sandbox-allow exec=$(which curl) npm install some-package

# Allow outbound connection to a private registry
pmg --sandbox-allow net-connect=npm.internal.corp:443 npm install @corp/private-pkg

# Allow a dev server to bind to a local port
pmg --sandbox-allow net-bind=127.0.0.1:3000 npx some-dev-tool

# Re-allow a sensitive environment variable that the profile scrubs by default
pmg --sandbox-allow env=GOOGLE_APPLICATION_CREDENTIALS npm install some-package

# Multiple overrides
pmg \
  --sandbox-allow "write=$HOME/.example-tool-cache/**" \
  --sandbox-allow exec=$(which curl) \
  npm install some-package
```

Supported types: `read`, `write`, `exec`, `net-connect`, `net-bind`, `env`, `preset`.
For one run, use `--sandbox-allow preset=git`.
A missing runtime preset warns and contributes no allowances.

A `net-bind` value, and each `network.allow_bind` entry of a profile, is `host:port`. The host is
loopback (`localhost`, `127.0.0.1`, `[::1]`) or all interfaces (`0.0.0.0`, `[::]`).
PMG warns for all-interface `net-bind` overrides.
Profile entries load without that warning, and presets reject them. PMG refuses any other
host, because no driver can limit a bind to it. The port is a number or `*`. A `net-bind` override
also turns on `allow_network_bind`, which allows every loopback port. Only macOS limits a bind to
the port of a profile `allow_bind` entry, and only when the profile does not set
`allow_network_bind`. Landlock does not restrict `bind` or `listen`.
A process can listen on any address and port regardless of this boolean.
Under proxy-only confinement, the boolean opens all loopback connects.
See [Landlock gaps](sandbox-landlock.md#network-lockdown-gaps).

For `env`, the value is an environment variable **name** or name glob (e.g. `NPM_TOKEN`,
`npm_config_*`) and is kept verbatim. It is not path-resolved. It is an allow-only override that
re-permits a variable the profile would otherwise scrub. An allow always wins, so there is no deny
list to edit. If a command fails with an auth error, re-run with `--debug` and look for a "scrubbed" log
line naming the variable, then re-allow it with `--sandbox-allow env=NAME`.

Overrides are non-persistent (apply to current invocation only) and logged in the event log for
auditing. An override adds the path to the allow list and removes an exact match entry from the
corresponding deny list after expansion.
An identical glob override removes that glob deny.
A narrower override does not. An exact-match entry in `allow_read`
or `allow_write` (in the policy or via `--sandbox-allow read=...` / `write=...`) opts out of the
mandatory deny for that credential file. PMG treats both channels as explicit user intent.
Suppression needs an exact match. Broad paths and globs do not opt out. `.git/hooks` does not
accept opt-outs.

### Project Overlays

A project overlay is a per-repository allow-set that PMG applies automatically on every sandboxed run in
that repo, so you do not have to retype the same `--sandbox-allow` flags. The overlay is local
only, keyed by the repo's git toplevel (CWD when not a git repo), and stored under
`<config_dir>/sandbox/overlays/`.
Entries use runtime override semantics and can remove equal deny entries or opt out of mandatory denies.
`.git/hooks` cannot be opted out.
The save command requires `--force` for its recognized sensitive paths and secret environment names.
That sensitive-path list does not cover every mandatory credential deny.
For example, `.git-credentials`, `.azure`, `.gcloud`, and `.config/gh` can be saved without that guard.
A hand-edited overlay also bypasses the save-time guard.
PMG ignores overlays under `global_lockdown`.

An older PMG saved `net-bind` entries that the current check refuses, such as `::1:5173`. PMG
ignores such an entry on every run and in `pmg sandbox project show`, and names it in a warning.
Save the entry again in the current form, for example `pmg sandbox allow net-bind=[::1]:5173`.
That save removes the ignored entries and keeps the others.

```bash
# Save manual allowances for the current repo
pmg sandbox allow "write=$HOME/.example-tool-cache/**" net-bind=localhost:4321

# Persist an environment variable allowance so the profile stops scrubbing it
# in this repo (same semantics as --sandbox-allow env=..., but saved)
pmg sandbox allow env=GOOGLE_APPLICATION_CREDENTIALS

# Promote the primary violation from the most recent cached report
pmg sandbox allow --last

# Promote every safe FS, exec and env violation from that report
pmg sandbox allow --last --all

# Allow a sensitive path (e.g. .env, .npmrc) explicitly
pmg sandbox allow --force read=./.env

# Inspect the current repo's overlay
pmg sandbox project show
pmg sandbox project show --json

# List overlays across all known repos
pmg sandbox project list

# Delete the current repo's overlay
pmg sandbox project reset --yes
```

### Presets

A preset is a named, additive-only bundle of allowances for one workload (git hooks tooling,
an Astro/Vite/Next.js dev server, ...). Instead of discovering allowances one denial at a
time, apply a curated bundle:

```bash
pmg sandbox preset list
pmg sandbox preset show git
pmg sandbox allow preset=git preset=astro
```

Presets can also be attached to a profile via a `presets:` list. See
[sandbox-presets.md](sandbox-presets.md) for usage and how to author your own.

Notes:

- `--last`/`--last --all` promotes filesystem, exec and environment denials. It does not
  promote a network denial, so a save after an unrelated denial cannot allow a destination the
  policy refused. Pass network allowances (`net-connect`, `net-bind`) as `type=value`.
  `pmg sandbox explain --last` prints the command for a refused destination.
- `pmg sandbox allow` refuses sensitive targets (`.env*`, `.npmrc`, `.ssh`, `.aws`, `.kube`,
  `.gnupg`, ...) unless `--force` is given.
- Applied overlay entries are recorded in the audit event log with a `+overlay` source tag so
  they can be distinguished from `--sandbox-allow` flags.

<details>
<summary>Custom policy overrides using Policy Templates</summary>

Policy templates allow custom policy overrides. To setup custom policy overrides for your package manager,
start by looking up the PMG configuration directory:

```bash
pmg setup info
```

Create a new policy template file in the PMG configuration directory and edit it to suit your needs:

```bash
# Set the PMG configuration directory
export PMG_CONFIG_DIR="/path/to/pmg/config/dir"

# Create the policy template file
cat > "$PMG_CONFIG_DIR/sandbox-custom-policy.yml" <<'EOF'
name: pnpm-macos-custom-sandbox
description: Custom pnpm cache access
inherits: pnpm
package_managers: [pnpm]
filesystem:
  allow_write:
    - ${HOME}/.example-tool-cache/**
EOF
```

Edit PMG configuration file to use the custom policy template and override the default
policy for your package manager:

```yaml
sandbox:
  policy_templates:
    pnpm-macos-custom-sandbox:
      path: ./sandbox-custom-policy.yml
  policies:
    pnpm:
      enabled: true
      profile: pnpm-macos-custom-sandbox
```

Next time you run `pmg pnpm install`, the custom policy template will be used instead of the default policy.

</details>

## Supported Platforms

| Platform | Supported | Implementation                      |
| -------- | --------- | ----------------------------------- |
| MacOS    | Yes       | Seatbelt sandbox-exec               |
| Linux    | amd64, arm64 | Landlock (default, kernel 5.13+) or Bubblewrap (fallback) |
| Windows  | No        | Not yet supported                   |

### Platform-Specific Limitations

<details>
<summary>Linux (Landlock, default)</summary>

**Default sandbox on kernel 5.13+**: Landlock provides kernel-native filesystem access control
without external binaries. The driver always creates a user namespace, so a non-root caller
needs unprivileged user namespaces.

For the architecture, design tradeoffs, and known limitations see
[sandbox-landlock.md](./sandbox-landlock.md).

**Deny enforcement.** Under a broad writable subtree, the seccomp supervisor supplies project denies that Landlock cannot subtract.
It checks a fixed path-syscall table, not every syscall with a path.
A process can race the path or symlink after the check.
Metadata calls such as chmod, chown, and utimensat are not trapped.
Treat these denies as a strong default rather than a hardened boundary.
Based globstar denies such as `${HOME}/**/*.pem` expand once and compare the suffix literally.
They can silently match nothing in an existing tree.
The walk stops at depth 5 or 1000 paths.
A bare `base/**` instead grants a directory and later descendants.
Allows with more than 100 matches can widen to their parent.
Missing rule paths are skipped.
See [Landlock details](sandbox-landlock.md).

**Deny enforcement across the process tree**: seccomp-notify resolves the path argument of
an intercepted `openat(2)` by reading `/proc/<pid>/mem` of the trapping process. PMG ships
this in a two-stage architecture so enforcement applies to direct targets AND every
descendant (grandchildren, great-grandchildren, etc.):

1. The helper process (`pmg __landlock_sandbox_exec`) clones a tiny shim
   (`pmg __landlock_shim`) with `CLONE_NEWUSER` and an identity uid/gid map. The same
   `clone()` creates the PID, IPC and mount namespaces, which need `CAP_SYS_ADMIN` in the
   new user namespace.
2. The shim applies Landlock, sets `PR_SET_NO_NEW_PRIVS`, installs the seccomp-notify
   filter, and `execve`s the real target. The target runs as the caller with no
   capability. A root caller maps to an unprivileged uid (65533, or 65532 when 65533 is the overflow UID) in the namespace, so
   tools never see uid 0. The mapped kernel uid stays 0, so the target owns the same
   files as the root caller. Access follows the permission bits. The target has no
   `CAP_DAC_OVERRIDE`.
3. The helper opens `/proc/<pid>/mem` for each descendant. The helper created the user
   namespace, so the kernel grants it `CAP_SYS_PTRACE` over the namespace. The read works
   after a task uses `PR_SET_DUMPABLE=0` under the created namespace.
   An unreadable executable owned outside the mapping can move the image's ptrace relationship to an ancestor namespace.
   The helper can then lose access and deny trapped calls.

**Fail closed when memory is unreadable**: the supervisor reads `/proc/<child>/mem` at
startup. If it cannot read it, the run stops. So a host that blocks the read stops the run
instead of running with no enforcement. Examples are a `hidepid` proc mount,
`kernel.yama.ptrace_scope=3`, and a hardening LSM. PMG does not fall back to Bubblewrap here.
Bubblewrap may not be installed. At runtime the supervisor denies a trapped path or exec
syscall when it cannot read the memory that holds the path. So a process cannot read a denied
file when the supervisor cannot inspect its path.
The ordinary dumpable change is not itself a bypass.
The execute-only binary exception above can make trapped operations fail.
Bubblewrap does not need process-memory reads but has different mount-layer limits.

The user namespace is purely a capability vehicle for the shim. The uid and gid map to
themselves, so targets see the caller's identity and the same filesystem ownership they
normally would. `id` prints the caller, and tools that change behaviour as root (npm
lifecycle scripts, pip's root warning) run as the caller. A root caller maps to an
unprivileged uid in the namespace, so these tools keep the non-root behavior.

**Requirements**: unprivileged user namespaces must be enabled (`unprivileged_userns_clone=1`
on Debian/Ubuntu, the default on most modern distros). If disabled, the helper fails with an
EPERM on `clone()` and the run stops.
PMG falls back only when its Landlock ABI probe fails.
Bubblewrap also needs user namespaces for an unprivileged run unless installed setuid root.

**Network filtering**: `network_via_proxy_only` lockdown is enforced by the seccomp
supervisor, which intercepts `connect`/`sendto`/`sendmsg` and confines outbound traffic
to the PMG proxy's loopback port (plus loopback when the profile sets `allow_network_bind`,
and port 53 when it sets `allow_direct_dns`). Denials surface as `network_connect`
violations. The fail-closed contract is the same as on macOS: no running proxy, no command.
Known gaps, including untrapped `sendmmsg`, address races, and loopback DNS are documented in
[sandbox-landlock.md](./sandbox-landlock.md). Outside lockdown there is no fine-grained
host filtering. PMG does not use the native port rules of Landlock V4 yet.

**PID/IPC namespace isolation**: Applied best-effort via `CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS`.
On `EPERM` or `EINVAL`, the helper warns and retries without PID, IPC, and paired mount isolation.
A profile allowing a non-self `/proc` path skips PID and mount isolation with a diagnostic warning. Set `PMG_SANDBOX_DRIVER=bubblewrap`
to force Bubblewrap if namespace isolation is required.

**`/proc` access.** Landlock uses the inherited host procfs even when PID namespace creation succeeds.
The driver grants `/proc` reads and drops authored proc denies.
Processes can inspect host entries subject to Unix permissions.
Only Bubblewrap mounts a procfs scoped to its PID namespace.
Select Bubblewrap if that boundary is required, subject to its profile limitations.

**Fallback**: If Landlock is unavailable (kernel < 5.13), Bubblewrap is used automatically.
Set `PMG_SANDBOX_DRIVER=bubblewrap` to force Bubblewrap.
Set `PMG_SANDBOX_DRIVER=landlock` to require Landlock without fallback.

</details>

<details>
<summary>Linux (Bubblewrap, fallback)</summary>

**Filesystem permissions are coarse-grained**: [Bubblewrap](https://github.com/containers/bubblewrap) uses bind mounts for filesystem isolation.

To prevent `Argument list too long` errors with large directory trees, PMG automatically uses
coarse-grained fallback strategies when glob patterns match many files.

**Fallback Behavior:**

- **Small patterns** (100 matches or fewer): Individual files are mounted (fine-grained, most precise)
- **Large patterns** (> 100 matches): Parent directory is mounted (coarse-grained, scalable)
- **Threshold**. More than 100 paths triggers fallback, including deny globs.

**Glob limits.** Bubblewrap permits depth 5 and up to 10000 glob paths.
Write globstars bind their base tree directly.
Other expansion can reflect only existing paths.

**Network filtering.** Bubblewrap can use `--unshare-net` for deny-all isolation.
It rejects `network_via_proxy_only`.
Proxy host rules apply only to clients that reach the proxy.

**Deny targets are mount points**: a denied file is masked with `/dev/null` and a denied directory
with a tmpfs. A mount point cannot be renamed or removed (`EBUSY`), which also blocks a rename of
the protected file to an unprotected name. rename(2) of an ancestor directory succeeds and takes
the overlay with it, so PMG also binds every directory between a writable base and a protected
path onto itself (`${CWD}/.git` under `allow_write: ${CWD}/**`). A process cannot move `.git`
aside and create a fresh `.git/hooks`.

**A deny target that does not exist is not enforced**: bwrap creates a missing mount point on the
host, which would leave an empty `.env` or `.github/workflows` in the project. PMG skips such
literal targets.
A missing `<dir>/**` write-deny directory can receive an empty read-only placeholder when its parent exists under a writable bind.
That empty host directory remains after the run.
Other missing literals, including `.env` and `.github/workflows`, are skipped.
Under a writable project tree a process can therefore create `.github/workflows` when the
repository has none. The Landlock driver denies the path by name and has no such gap.

**Per-direction mandatory deny is asymmetric under Bubblewrap.** bwrap has no primitive that allows writes
while denying reads for the same path. `--bind` exposes both directions. `--tmpfs` and
`--ro-bind /dev/null` block both. If you opt out of write for a mandatory deny path (e.g., list it
in `allow_write` but not `allow_read`), the bind mount also exposes reads, and PMG cannot enforce
the read-side mandatory deny. PMG warns via `log.Warnf` when it detects this case. macOS Seatbelt
and Landlock enforce read and write denies independently.

**Violation reporting is best effort**: Bubblewrap isolates with namespaces and mounts rather than
a security module, so it never observes a denial. The kernel fails the syscall and the sandboxed
program reports the error itself. PMG reads the command's output and matches the trailing
`strerror(3)` phrase, which is identical across programs even though the message prefix is not.

Recognised: `Permission denied`, `Operation not permitted`, `Read-only file system`, and exec
failures bwrap reports itself. Denials from shell install scripts and the coreutils they call are
covered, including paths that are quoted, contain spaces, or contain a colon.

Not reported:

- A path absent from the sandbox fails with `No such file or directory`, which is
  indistinguishable from a file that never existed. Reporting it would flag every genuinely
  missing file, so it is skipped unless bwrap itself reports it for a failed exec.
- Language runtimes that print the path after the errno phrase rather than before it, such as
  Node and Python.
- A bare name carrying neither a separator nor an extension, such as `Makefile`. The trailing
  token of an error line is often prose, so a target must look like a path to be accepted.
- A denial on a host that sets `LC_ALL`. libc translates `strerror(3)`, so PMG pins
  `LC_MESSAGES=C` for the sandboxed command to keep those phrases in English. `LC_ALL` outranks
  `LC_MESSAGES`, and overriding it would change number formatting and collation for every build
  script in the install, which is too broad a side effect for a diagnostics feature.

Reports from this driver are marked as derived from the command's output. Because a malicious
package can print a denial that never happened and name any target it likes, these violations are
shown by `violations list` and `explain` but never become an override suggestion, and
`pmg sandbox allow --last` will not persist them.

Landlock and Seatbelt do not share these limits. Both read a dedicated kernel or platform channel
rather than the command's output.

</details>

<details>
<summary>macOS (Seatbelt)</summary>

**Network lockdown (`network_via_proxy_only`)**: Fine-grained `host:port` filtering is not
expressible in Seatbelt, so per-host control happens at the PMG proxy instead. With
`network_via_proxy_only: true`, the sandbox denies all non-loopback outbound network. Only the
running PMG proxy's port is reachable, and profiles with `allow_network_bind` additionally keep
loopback↔loopback connects open. Raw sockets, QUIC, and arbitrary non-loopback ports are blocked
at the kernel.
Direct DNS is disabled by default, because the proxy resolves names. `allow_direct_dns: true`
re-opens it. The Go, Cargo, and exec profiles ship with proxy-only confinement.
Remote DNS opens only with `allow_direct_dns`, but permitted loopback ports can reach a local resolver.

**Deny targets are pinned against a move**: Seatbelt checks a rename against its source and its
destination only, so a denied file would move along with its parent directory and a prepared
directory could be renamed into the parent's place. PMG denies `file-write-unlink` on the target
and on every directory above it up to the `allow_write` base that makes it movable, so
`mv ~/.claude ~/.cache/old` fails under the claude preset. A parent that does not exist yet cannot be pinned, because Seatbelt
cannot tell a rename onto it from the `mkdir` the agent needs.

Lockdown is fail-closed: it requires the proxy flow, and pmg errors out rather than running
without confinement when no proxy is available. Linux enforces the same contract with the
Landlock driver, which intercepts `connect` in its supervisor. See
[sandbox-landlock.md](./sandbox-landlock.md). The Bubblewrap fallback driver still rejects
lockdown profiles with a clear error rather than running unconfined.

For local development:

- With sandboxing enabled, `npm run dev` and unknown commands remain sandboxed. Known non-download commands need `enforce_always` for coverage.
- Loopback↔loopback traffic keeps working via `allow_network_bind`, as noted above.
- Proxy-aware clients use CONNECT. Audit mode permits denied destinations, while enforce mode refuses matches.

What breaks under
lockdown is direct non-loopback sockets — tools that ignore `HTTP_PROXY`/`HTTPS_PROXY` and
non-HTTP wire protocols (e.g. Postgres or Redis clients pointed at non-loopback hosts). Such
denials render as:

> direct network access blocked by network_via_proxy_only — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)

</details>

## Concepts

PMG layers three concepts: a **Policy** is the rule set defining what is allowed and denied. A
**Profile** is a named binding from a package manager to a policy. A **Policy Template** maps a
profile name to a YAML file so you can override the built-ins.

<details>
<summary>Detailed concepts</summary>

### Policy

Policy is a set of rules that define the allowed and denied actions for a package manager. A sandbox implementation, such as
`sandbox-exec` on MacOS enforces the policy.

PMG defines its own policy model. The design goal is simplicity and ease of use. Sandbox implementations are expected to translate
the policy model into their own native policy format. Rules for policy are:

- Filesystem access requires an applicable grant, and filesystem denies take precedence where supported.
- Execution allowances are additive and driver-specific. Network rules use specificity, and environment allows win.
- Policy profile allows binding package managers to a specific sandbox policy
- Package manager must have a sandbox profile when sandbox is enabled
- Package manager specific sandbox profile may be disabled to skip sandbox for the package manager

### Profile

Profile is a named reference to a policy. It is used to associate a policy with a package manager. PMG ships with a set of built-in profiles
that are used to enforce the policies for the package manager. See [sandbox/profiles](../sandbox/profiles) for the list of built-in profiles.

Create a child with `pmg sandbox profile init <name> --from <builtin> --package-manager <pm>`, then add rules with `profile edit`.
The child continues to receive inherited base updates.
See [sandbox/profiles/README.md](../sandbox/profiles/README.md) for more details.

### Policy Template

Policy template is a configuration primitive for overriding a built-in profile or creating a custom profile. It is used to map a profile name to a path.
See [config/config.template.yml](../config/config.template.yml) for an example.

### Network rules

The `network.allow_outbound` and `network.deny_outbound` lists hold rules of the form
`host:port`, with an optional client part, `<exe>=host:port`.

- `host` is a name, compared without case and without a trailing dot. `*.example.com` matches
  one or more labels before `example.com` and not `example.com` itself. `*` matches every host.
  An IPv4 or IPv6 literal is a host. An IPv6 literal is written in brackets, `[2001:db8::1]:443`.
  The proxy compares a connection's host as the transport dials it: a name is mapped with IDNA,
  so a fullwidth letter or a soft hyphen in a request names the plain host, an address in a
  short or octal form such as `127.1` is `127.0.0.1`, and an IPv6 zone is dropped. A host the
  proxy cannot read as a name or an address is denied.
- `port` is a number from 1 to 65535, or `*`.
- `<exe>` is an absolute path or a bare program name, such as `git=github.com:443`. The
  proxy cannot name the program behind a connection yet, so a profile with a client rule
  fails to load and `pmg sandbox profile lint` reports it.

The most specific matching rule wins. An exact host beats a wildcard, a longer wildcard suffix
beats a shorter one, and every host rule beats `*`. At equal host specificity an exact port
beats `*`. At equal specificity deny wins. With no matching rule the connection is allowed, so a
profile that wants an allow list denies `*:*`.

`network.deny_ip_literals: true` denies an IP literal with the rule `ip_literal`. An IP literal
is an address and not a name. An allow rule that names that exact address wins. Its port may be
`*`. A wildcard host never names an address, so `*:*` does not allow one. Loopback addresses stay with the
rules. The key is off by default.

A broad allow such as `*:*` or `*:443`, or a deny-list policy naming only domains, can permit IP destinations.
A names-only allow list ending in a `*:*` deny already refuses other addresses.
The key preserves that refusal if a later rule allows broadly. `pmg sandbox profile propose` writes `true` unless the target
already set the key. A child profile that sets the key wins over its parent. Under
`global_lockdown` the daemon refuses a profile that does not keep a locked `true`. An older
`pmg` ignores the key, so a team that shares profiles needs a version that reads it on every
host.

The PMG proxy applies the rules to every connection it sees: a CONNECT, a redirected TLS
connection, a plain HTTP request, and a request inside a terminated tunnel. The rules are a
applied only to traffic that reaches the proxy.
Proxy-only confinement has the [Landlock gaps](sandbox-landlock.md#network-lockdown-gaps) and loopback or DNS openings described above.
Persistent-proxy [kernel enforcement](persistent-proxy.md#kernel-enforcement-linux) routes eligible TCP on configured ports, default 80 and 443, subject to its exemptions.
Other ports and bypass paths remain outside that policy. `pmg sandbox exec` runs a proxy of its own for the program. See
[Network](sandbox-exec.md#network) in the exec guide.

A one-shot package-manager proxy receives these rules only when that run's sandbox scope is enabled.
A restrictive profile and enforce mode alone do not filter a sandbox-disabled run.
`sandbox.network_mode` controls the enabled one-shot sandbox proxy and `pmg sandbox exec`.
Exec also accepts `--network-mode`.
The persistent daemon instead reads `proxy.server.profile` and `proxy.server.network_mode`.
See its [network policy](persistent-proxy.md#network-policy).

- `audit` (default): the proxy records the match and lets the connection through. The report
  lists the destinations the rules would deny.
- `enforce`: the proxy refuses the connection. A proxy-aware client gets a 403 that names the
  destination and the rule. A redirected TLS connection is closed before the handshake. The
  report lists the refused destinations, and `pmg sandbox explain --last` and
  `pmg sandbox allow net-connect=<host>:<port>` work on them. `--sandbox-allow
  net-connect=<host>:<port>` allows one destination for one run and removes an exact deny.

The mode lives in the config and not in the profile, so one profile can run in audit on one host
and in enforce on another. Every match writes a `network_policy` event to the event log.

A run with observed destinations writes a `network_observation` event when event logging is enabled.
The report names its run ID when available. `pmg sandbox profile propose --run <id>` turns the run into
the `network` block of a profile: one allow rule per host and port, `deny_ip_literals: true`,
plus a catch-all deny. Hosts the inherited built-in profile already allows are not repeated. A
destination the run refused under `enforce` gets no rule, because the program never reached it. `--last` uses the newest run of
this repository. `--since 30d` merges every run of the repository in the window. `--new <name>`
writes a user profile. `--into <path>` adds the rules to a profile and keeps its other blocks.
Without a target the command prints the table and the block. `--dry-run` shows what a target would
get. The command reads the event log, so `skip_event_logging` must be off. With event logging off
the report names no run. The other sections of a profile come from violations, not observation.
Promote them with `pmg sandbox allow --last --all`.

`pmg sandbox profile lint` reports a rule the proxy cannot parse as an error, and warns when
`allow_direct_dns` is set under `network_via_proxy_only`, because DNS is a path past the rules. A
profile with a rule the proxy cannot parse does not run.

</details>

## Threat Model

PMG trusts policy files and the operator's CLI as the source of intent. The sandbox implementation
translates that intent with driver-specific limitations. Translation from PMG's YAML to the native sandbox format must
preserve the intended boundary.
Current drivers have the documented translation gaps above.
Bubblewrap can coarsen grants, skip missing denies, and expose reads through write opt-outs.
Treat these as limits of the implementation.
Keep interpolation inputs trusted.

<details>
<summary>Detailed assumptions</summary>

- Policy files are trusted
- Policy enforcement is a sandbox implementation concern
- YAML to sandbox specific policy translation must not make the policy weaker than the original policy
- Variable interpolation in policy files must consider only trusted sources

</details>

## Enforcement

The OS sandbox refuses operations that its policy denies.
A refusal fails that operation, and a program can catch the error and continue.
Proxy-only direct network refusal has the driver limitations above.
The proxy applies host rules separately.
Audit mode records a denied match and permits it.
Set `sandbox.network_mode: enforce` to refuse proxy connections.
See [Network rules](#network-rules).

## Debug

### MacOS

OSX sandbox implementation is based on [Chromium OSX Sandbox Design](https://www.chromium.org/developers/design-documents/sandbox/osx-sandboxing-design/)
and [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime).

PMG records Seatbelt denials in the violation cache. Inspect them with `pmg sandbox violations list`
and `pmg sandbox explain --last`.

To see every raw denial of a run, also the ones that PMG does not record after a clean run, run the
command with debug logging:

```bash
APP_LOG_LEVEL=debug APP_LOG_FILE=/tmp/pmg-debug.log pmg --sandbox npm install express
```

Get the log tag of the run from the debug log file.

```bash
TAG=$(grep -o "PMG_SBX_[A-Z0-9]*" /tmp/pmg-debug.log | tail -1)
```

Use `log(1)` to show the denials that carry the tag. Give its full path, because zsh has a
built-in `log` command.

```bash
/usr/bin/log show --last 5m --predicate "eventMessage CONTAINS \"$TAG\"" --style compact
```

### Linux

Landlock is the default Linux driver.
Use `pmg sandbox violations list`, `pmg sandbox explain --last`, and [Landlock tracing](sandbox-landlock.md#debugging-pmg_seccomp_trace).
Inspect native policy before running it with `pmg sandbox profile show npm --driver landlock` on Linux.
Use `--driver seatbelt` on macOS or `--driver bubblewrap` on Linux for those renderers.
The renderer supports explicit HOME and CWD expansion options through its help.

For the Bubblewrap driver, force selection while capturing the full wrapped command.

```sh
PMG_SANDBOX_DRIVER=bubblewrap pmg --debug --log /tmp/pmg-debug.log --sandbox npm install express
grep 'Sandboxed command:' /tmp/pmg-debug.log
```

Replay only a reviewed, current command from that log.
The shorter `Bubblewrap arguments` line omits the seccomp shim.
Bubblewrap has no `--verbose` option.
For syscall detail, run the full command under `strace -f` on a disposable environment.
Bubblewrap denials commonly appear as EROFS or ENOENT rather than EACCES.
A file masked with `/dev/null` can read as empty.
PMG records only the command-output denials it recognizes.

See [Development](development.md) for the contributor test map and [profile rendering](sandbox-landlock.md#debugging-pmg_seccomp_trace) for inspection.

### AppArmor blocks the Landlock driver (Ubuntu 23.10+)

Ubuntu restricts unprivileged user namespaces via AppArmor
(`kernel.apparmor_restrict_unprivileged_userns=1`, added in 23.10 and enabled by default since 24.04). The Landlock driver needs
one: it re-executes pmg inside a user namespace to install its seccomp filter. With the restriction
active, sandboxed commands fail with:

```
Error: start shim (retry): ... permission denied
```

`pmg sandbox doctor` reads the sysctl for its "AppArmor user namespaces" check.
It can keep warning after the per-PMG profile is loaded because the sysctl remains 1.
The Landlock canary check confirms whether execution now works.

The recommended fix is Ubuntu's own mechanism: an AppArmor profile that grants pmg (and only pmg)
the `userns` permission.
Create `/etc/apparmor.d/pmg` with the actual native binary path.
`command -v pmg` suffices for the install-script layout.
For Homebrew, resolve its link with `readlink -f`, or use a version-directory glob such as `/home/linuxbrew/.linuxbrew/Cellar/pmg/*/bin/pmg`.
For npm, locate the installed `@safedep/pmg-linux-<arch>/bin/pmg` optional package beneath the launcher.
For mise, name the native binary under its installs directory, not its shim.
A profile attached to a launcher or shim does not authorize the native helper.

```
abi <abi/4.0>,
include <tunables/global>

profile pmg /usr/local/bin/pmg flags=(unconfined) {
  userns,
  include if exists <local/pmg>
}
```

Load it. It persists across reboots, and no restart is needed.

```bash
sudo apparmor_parser -r /etc/apparmor.d/pmg
```

Alternatively, disable the restriction system-wide. This is simpler but weakens the protection for
every binary on the host, so prefer the profile:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

This change lasts until reboot.
To persist it, put `kernel.apparmor_restrict_unprivileged_userns=0` in a file under `/etc/sysctl.d/`.

## References

- <https://github.com/anthropics/sandbox-runtime>
- <https://geminicli.com/docs/cli/sandbox/>
- <https://github.com/containers/bubblewrap>
