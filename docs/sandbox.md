# Sandbox

PMG sandbox design goal is to protect against unknown supply chain attacks using principle of least privilege.

We do not want to re-invent sandbox and likely rely on OS native sandbox primitives. This is at the cost of developer experience,
where we have to work within the limitations of the sandbox implementations that we use.

## Security Model

- **Default deny**: All operations are blocked unless explicitly allowed by the policy. An empty policy grants no access.
- **Deny rules override allow rules**: When a path appears in both allow and deny lists, the deny rule wins. Deny rules are placed after allow rules in the generated sandbox profile to ensure this.
- **Credential and sensitive file protection**: The sandbox automatically blocks read and write access to credential files regardless of user configuration. Protected files include `.env`, `.env.*`, `.aws`, `.gcloud`, `.kube`, `.ssh`, `.gnupg`, and `.docker/config.json`. These mandatory deny patterns are injected at translation time and cannot be removed by policy configuration or runtime overrides.
- **Git hooks are always blocked**: Write access to `.git/hooks/` in both `$CWD` and `$HOME` is always denied to prevent arbitrary code execution via repository hooks.
- **Git config is blocked by default**: Write access to `.git/config` is denied unless `allow_git_config: true` is set in the policy. This prevents credential helper manipulation.
- **Runtime overrides remove only exact-match deny entries**: When `--sandbox-allow` adds a path to an allow list, only a literal string match in the corresponding deny list is removed. Glob and wildcard deny patterns (e.g., `/etc/**`) are never removed. Mandatory deny patterns (credentials, git hooks) cannot be overridden because they are re-injected at translation time.
- **Profile inheritance is single-level**: A profile can inherit from one built-in profile. Allow and deny lists are merged using union semantics. Boolean fields (`allow_pty`, `allow_git_config`) in the child override the parent.
- **Variable expansion is runtime-only**: Policy paths use `${HOME}`, `${CWD}`, and `${TMPDIR}` which are expanded when the sandbox is set up, not when the policy is defined.
- **Process-level isolation only**: The sandbox restricts the package manager process and its children. It does not enforce CPU, memory, or disk quotas. Network filtering is coarse-grained — host-level filtering is not enforced on either platform.

## Requirements

- Bubblewrap on Linux
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

- Make sure sandbox is enabled in your `config.yml` file.
- Make sure sandbox profiles are configured for the package managers you want to sandbox.
  
See [configuration](./config.md) and [config/config.template.yml](../config/config.template.yml) for the configuration schema.
Once sandbox is enabled, you can run package manager commands with sandbox protection.

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

### Runtime Allow Overrides

Use `--sandbox-allow` to make one-off exceptions without creating a custom profile. This is useful when a command needs access that the default profile blocks.

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

Overrides are non-persistent (apply to current invocation only) and logged in the event log for auditing. An override adds the path to the allow list and removes an exact match entry from the corresponding deny list. Glob deny patterns are never removed. Mandatory security protections (`.env`, `.ssh`, `.aws`, `.git/hooks`, etc.) cannot be bypassed by overrides.

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
| Linux    | Yes       | Bubblewrap with namespace isolation |
| Windows  | No        | Not yet supported                   |

### Platform-Specific Limitations

<details>
<summary>Linux (Bubblewrap)</summary>

**Filesystem permissions are coarse-grained**: [Bubblewrap](https://github.com/containers/bubblewrap) uses bind mounts for filesystem isolation.

To prevent `Argument list too long` errors with large directory trees, PMG automatically uses
coarse-grained fallback strategies when glob patterns match many files.

**Fallback Behavior:**

- **Small patterns** (< 100 matches): Individual files are mounted (fine-grained, most precise)
- **Large patterns** (> 100 matches): Parent directory is mounted (coarse-grained, scalable)
- **Threshold**: 100 paths per pattern triggers coarse-grained fallback

**Network filtering**: All-or-nothing network isolation (via `--unshare-net`). Host-specific
filtering is not enforced.

</details>

<details>
<summary>macOS (Seatbelt)</summary>

**Network filtering is limited**: Seatbelt supports network rules in policies, but fine-grained `host:port` filtering is not enforced.

</details>

## Concepts

1. Policy
2. Profile
3. Policy Template

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

## Threat Model

- Policy files are trusted
- Policy enforcement is a sandbox implementation concern
- YAML to sandbox specific policy translation must not make the policy weaker than the original policy
- Variable interpolation in policy files must consider only trusted sources

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
