# Sandbox

PMG sandbox design goal is to protect against unknown supply chain attacks using principle of least privilege.

We do not want to re-invent sandbox and rely on OS native sandbox primitives. This is at the cost of
developer experience, where we have to work within the limitations of the sandbox implementations
that we use.

## Security Model

The sandbox is default-deny. Every operation is blocked unless the policy allows it, and deny rules
win over allow rules when both match. PMG ships mandatory denies for credential files (`.env`,
`.ssh`, `.aws`, `.gcloud` and more). See [dangerous.go](../sandbox/dangerous.go) for the full list.
This protects against accidental credential leaks and some classes of supply chain attacks that
attempt to access credentials. To allow legitimate access, you can opt out of a mandatory deny
via an exact match entry in `allow_read` or `allow_write` (in the policy or via `--sandbox-allow`).

<details>
<summary>Detailed rules</summary>

- **Default deny**: All operations are blocked unless explicitly allowed by the policy. An empty policy grants no access.
- **Deny rules override allow rules**: When a path appears in both allow and deny lists, the deny rule wins. Deny rules are placed after allow rules in the generated sandbox profile to ensure this.
- **Credential and sensitive file protection**: The sandbox blocks read and write access to known list of credential files by default.
- **Git hooks are always blocked**: Write access to `.git/hooks/` in both `$CWD` and `$HOME` is always denied to prevent arbitrary code execution via repository hooks.
- **Git config is blocked by default**: Write access to `.git/config` is denied unless `allow_git_config: true` is set in the policy. This prevents credential helper manipulation.
- **Runtime overrides remove only exact-match deny entries**: When `--sandbox-allow` adds a path to an allow list, only a literal string match in the corresponding deny list is removed. Glob and wildcard deny patterns (e.g., `/etc/**`) are never removed. An exact-match entry in `allow_read` or `allow_write` (policy or runtime) opts out of the mandatory deny for that credential file. `.git/hooks` does not accept opt-outs.
- **Profile inheritance is single-level**: A profile can inherit from one built-in profile. Allow and deny lists are merged using union semantics. Boolean fields (`allow_pty`, `allow_git_config`) in the child override the parent.
- **Variable expansion is runtime-only**: Policy paths use `${HOME}`, `${CWD}`, and `${TMPDIR}` which are expanded when the sandbox is set up, not when the policy is defined.
- **Process-level isolation only**: The sandbox restricts the package manager process and its children. It does not enforce CPU, memory, or disk quotas. Network filtering is coarse-grained — host-level filtering is not enforced on either platform.

</details>

### Mandatory Credential Protection

PMG maintains a known list of credential and sensitive files at
[dangerous.go](../sandbox/dangerous.go) that are blocked by default in the sandbox. PMG injects three deny patterns per file:

- The path under `${CWD}`
- The path under `${HOME}`
- A `**/<file>` glob.

To opt out, list the literal path in `allow_read` or `allow_write` in your policy, or pass
`--sandbox-allow read=...` / `write=...` at runtime. Listing a CWD-absolute or HOME-absolute path
also suppresses the matching `**/<file>` glob on the same direction, so `--sandbox-allow
read=./.env` is enough to read `${CWD}/.env`. Suppression is exact post-expansion match; broad globs
like `${HOME}/**` do not opt out of `${HOME}/.aws`. The unnamed absolute form stays denied.
`.git/hooks` does not accept opt-outs because hooks can execute arbitrary code.

## Requirements

- Linux kernel 5.13+ with Landlock enabled (default, no external dependencies)
- Bubblewrap on Linux (fallback for kernels < 5.13, or when `PMG_SANDBOX_DRIVER=bubblewrap` is set)
- Seatbelt on MacOS

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
Once sandbox is enabled, you can run package manager commands with sandbox protection.

Run `pmg sandbox doctor` to see platform specific sandbox setup and driver status. Continue using
PMG as usual, sandbox will be applied to configured package managers automatically.

```bash
pmg npm install express
```

Explicitly enable sandbox if not enabled in the `config.yml` file:

```bash
pmg --sandbox --sandbox-profile=npm-restrictive npm install express
```

Run sandbox with custom policy file:

```bash
pmg --sandbox --sandbox-profile=/path/to/custom-policy.yml npm install express
```

### Sandbox Profile Commands

Use profile commands to inspect, create, and validate sandbox profiles.

```bash
# List built-in and user profiles
pmg sandbox profile list

# Scaffold a user profile that inherits from a built-in
pmg sandbox profile init my-npm --from npm-restrictive

# Show a profile, or its fully resolved policy
pmg sandbox profile show npm-restrictive
pmg sandbox profile show npm-restrictive --resolved

# Lint a built-in, user profile, or profile file
pmg sandbox profile lint npm-restrictive
pmg sandbox profile lint ./my-profile.yml --strict

# Compare two resolved profiles
pmg sandbox profile diff npm-restrictive pypi-restrictive
```

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
pmg sandbox profile show npm-restrictive --resolved
```

`pmg sandbox doctor` runs platform-specific checks for the current host. Cached violation reports
used by `violations list` and `explain --last` are currently produced by macOS Seatbelt diagnostics;
on Linux, Bubblewrap and Landlock denials may only appear as command errors such as `EACCES`.

### Runtime Allow Overrides

Use `--sandbox-allow` to make one-off exceptions without creating a custom profile. This is useful
when a command needs access that the default profile blocks.

```bash
# Allow writing to a specific file
pmg --sandbox-allow write=./.gitignore npx create-next-app@latest

# Allow executing a binary blocked by the profile
pmg --sandbox-allow exec=$(which curl) npm install some-package

# Allow outbound connection to a private registry
pmg --sandbox-allow net-connect=npm.internal.corp:443 npm install @corp/private-pkg

# Allow a dev server to bind to a local port
pmg --sandbox-allow net-bind=127.0.0.1:3000 npx some-dev-tool

# Multiple overrides
pmg \
  --sandbox-allow write=./.gitignore \
  --sandbox-allow exec=$(which curl) \
  npm install some-package
```

Supported types: `read`, `write`, `exec`, `net-connect`, `net-bind`.

Overrides are non-persistent (apply to current invocation only) and logged in the event log for
auditing. An override adds the path to the allow list and removes an exact match entry from the
corresponding deny list. Glob deny patterns are never removed. An exact-match entry in `allow_read`
or `allow_write` (in the policy or via `--sandbox-allow read=...` / `write=...`) opts out of the
mandatory deny for that credential file. PMG treats both channels as explicit user intent.
Suppression is exact-match only; broad paths or globs do not opt out. `.git/hooks` does not accept
opt-outs.

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
cat > $PMG_CONFIG_DIR/sandbox-custom-policy.yml <<EOF
name: pnpm-macos-custom-sandbox
description: Custom profile for pnpm in MacOS
inherits: npm-restrictive

package_managers:
  - pnpm

allow_pty: true

filesystem:
  allow_write:
    # pnpm i need write access here
    - ${HOME}/Library/pnpm/.tools/**

    # pnpm i creates these tmp files in local dir, at least on MacOS
    - ${CWD}/_tmp_*

    # pnpm self-update (or likely update) creates temporary package.json files
    # for writing. This is likely for atomic update using filesystem rename operation
    # which guarantees atomicity
    - ${CWD}/package.json.*

    # Need access for dependency resolution
    - ${CWD}/.pnpm-store

  # Additional deny rules for extra security
  deny_write:
    - ${CWD}/.env
    - ${CWD}/.env.*
EOF
```

Edit PMG configuration file to use the custom policy template and override the default
policy for your package manager:

```yaml
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
| Linux    | Yes       | Landlock (default, kernel 5.13+) or Bubblewrap (fallback) |
| Windows  | No        | Not yet supported                   |

### Platform-Specific Limitations

<details>
<summary>Linux (Landlock, default)</summary>

**Default sandbox on kernel 5.13+**: Landlock provides kernel-native filesystem access control
without requiring external binaries or unprivileged user namespaces.

For the architecture, design tradeoffs, and known limitations see
[sandbox-landlock.md](./sandbox-landlock.md).

**Deny enforcement**: Deny rules (DenyRead, DenyWrite, DenyExec) are enforced via seccomp
user notifications. This introduces a small TOCTOU window (microseconds) between reading
the path and responding.

**Deny enforcement across the process tree**: seccomp-notify resolves the path argument of
an intercepted `openat(2)` by reading `/proc/<pid>/mem` of the trapping process. PMG ships
this in a two-stage architecture so enforcement applies to direct targets AND every
descendant (grandchildren, great-grandchildren, etc.):

1. The helper process (`pmg __landlock_sandbox_exec`) clones a tiny shim
   (`pmg __landlock_shim`) with `CLONE_NEWUSER` and a uid/gid map of `0 -> host uid`.
   The shim runs as uid 0 inside a fresh user namespace so it has `CAP_SYS_ADMIN` in that
   namespace.
2. The shim installs the seccomp-notify filter **without** `PR_SET_NO_NEW_PRIVS` (permitted
   by `CAP_SYS_ADMIN` in the ns). It then applies Landlock and `execve`s the real target.
3. Because `NO_NEW_PRIVS` was never set, subsequent `execve` calls in the tree do **not**
   reset `dumpable` to 0, so the helper can keep opening `/proc/<pid>/mem` for any
   descendant. Deny rules like `~/.ssh` are enforced for the full process tree.

The user namespace is purely a capability vehicle. Host uid/gid are preserved through the
mapping, so targets see the same filesystem ownership they normally would. Tools that
refuse to run as root (npm's root-in-container warning) are unaffected because the
outside-view uid never changes.

**Requirements**: unprivileged user namespaces must be enabled (`unprivileged_userns_clone=1`
on Debian/Ubuntu; default on most modern distros). If disabled, the helper fails with an
EPERM on `clone()` and the sandbox falls back to Bubblewrap.

**Network filtering**: Not enforced. Landlock supports TCP port filtering only (V4+, no hostname).
Use `--proxy-mode` for network control.

**PID/IPC namespace isolation**: Applied best-effort via `CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS`.
If unavailable, a warning is printed and the command continues. Set `PMG_SANDBOX_DRIVER=bubblewrap`
to force Bubblewrap if namespace isolation is required.

**`/proc` access**: The sandbox supervisor requires `/proc` read access. When PID namespace
isolation succeeds, `/proc` is scoped to the child's namespace. When it fails, `/proc`
exposes all system processes.

**Fallback**: If Landlock is unavailable (kernel < 5.13), Bubblewrap is used automatically.
Set `PMG_SANDBOX_DRIVER=bubblewrap` to force Bubblewrap.

</details>

<details>
<summary>Linux (Bubblewrap, fallback)</summary>

**Filesystem permissions are coarse-grained**: [Bubblewrap](https://github.com/containers/bubblewrap) uses bind mounts for filesystem isolation.

To prevent `Argument list too long` errors with large directory trees, PMG automatically uses
coarse-grained fallback strategies when glob patterns match many files.

**Fallback Behavior:**

- **Small patterns** (< 100 matches): Individual files are mounted (fine-grained, most precise)
- **Large patterns** (> 100 matches): Parent directory is mounted (coarse-grained, scalable)
- **Threshold**: 100 paths per pattern triggers coarse-grained fallback

**Network filtering**: All-or-nothing network isolation (via `--unshare-net`). Host-specific
filtering is not enforced.

**Per-direction mandatory deny is asymmetric on Linux**: bwrap has no primitive that allows writes
while denying reads for the same path. `--bind` exposes both directions; `--tmpfs` and
`--ro-bind /dev/null` block both. If you opt out of write for a mandatory deny path (e.g., list it
in `allow_write` but not `allow_read`), the bind mount also exposes reads, and PMG cannot enforce
the read-side mandatory deny. PMG warns via `log.Warnf` when it detects this case. macOS Seatbelt
does not have this limitation; its `file-read*` and `file-write*` rules are independent.

</details>

<details>
<summary>macOS (Seatbelt)</summary>

**Network filtering is limited**: Seatbelt supports network rules in policies, but fine-grained `host:port` filtering is not enforced.

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

- Deny by default unless explicitly allowed
- Deny rules have higher priority than allow rules
- Policy profile allows binding package managers to a specific sandbox policy
- Package manager must have a sandbox profile when sandbox is enabled
- Package manager specific sandbox profile may be disabled to skip sandbox for the package manager

### Profile

Profile is a named reference to a policy. It is used to associate a policy with a package manager. PMG ships with a set of built-in profiles
that are used to enforce the policies for the package manager. See [sandbox/profiles](../sandbox/profiles) for the list of built-in profiles.

Custom profiles can be created by copying a built-in profile and modifying the rules to suit the needs.
See [sandbox/profiles/README.md](../sandbox/profiles/README.md) for more details.

### Policy Template

Policy template is a configuration primitive for overriding a built-in profile or creating a custom profile. It is used to map a profile name to a path.
See [config/config.template.yml](../config/config.template.yml) for an example.

</details>

## Threat Model

PMG trusts policy files and the operator's CLI as the source of intent. The sandbox implementation
enforces what the policy declares. Translation from PMG's YAML to the native sandbox format must
not weaken it. Variable interpolation consumes only trusted sources.

<details>
<summary>Detailed assumptions</summary>

- Policy files are trusted
- Policy enforcement is a sandbox implementation concern
- YAML to sandbox specific policy translation must not make the policy weaker than the original policy
- Variable interpolation in policy files must consider only trusted sources

</details>

## Enforcement

The sandbox implementation currently only support `block` mode. This means, any policy violation will block the execution of the
package manager command.

## Debug

### MacOS

OSX sandbox implementation is based on [Chromium OSX Sandbox Design](https://www.chromium.org/developers/design-documents/sandbox/osx-sandboxing-design/)
and [Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime). Current implementation does not support
identifying sandbox policy violations.

To manually investigate sandbox policy violations, you can use the following command:

```bash
APP_LOG_LEVEL=debug APP_LOG_FILE=/tmp/pmg-debug.log pmg --sandbox --sandbox-profile=npm-restrictive npm install express
```

Find the log tag in the debug log file and use it to investigate the sandbox policy violation.

```bash
grep "PMG_SBX_" /tmp/pmg-debug.log
```

Use `log(1)` to filter the log file by the log tag.

```bash
log show --last 5m --predicate 'message ENDSWITH "PMG_SBX_${TAG}"' --style compact
```

### Linux

Linux sandbox implementation uses Bubblewrap for namespace-based isolation. Enable debug logging to see translated sandbox arguments:

```bash
APP_LOG_LEVEL=debug APP_LOG_FILE=/tmp/pmg-debug.log pmg --sandbox --sandbox-profile=npm-restrictive npm install express
```

Review the debug log to see the translated `bwrap` command-line arguments:

```bash
grep "Bubblewrap arguments" /tmp/pmg-debug.log
```

To debug sandbox violations, you can manually test commands with increased verbosity by running the sandbox command directly:

```bash
# Extract the bwrap command from debug logs and run with --verbose
bwrap --verbose [arguments...] -- npm install express
```

**Note**: Unlike macOS, Bubblewrap does not provide real-time violation logging. Policy violations typically manifest as `EACCES` (Permission denied) errors.

## References

- <https://github.com/anthropic-experimental/sandbox-runtime>
- <https://geminicli.com/docs/cli/sandbox/>
- <https://github.com/containers/bubblewrap>
