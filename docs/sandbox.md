# Sandbox

PMG sandbox design goal is to protect against unknown supply chain attacks using principle of least privilege.

We do not want to re-invent sandbox and likely rely on OS native sandbox primitives. This is at the cost of developer experience,
where we have to work within the limitations of the sandbox implementations that we use.

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

**Linux (Bubblewrap)**:
- **Filesystem permissions are coarse-grained**: Linux sandbox uses bind mounts for filesystem isolation. When you specify a glob pattern like `${CWD}/*.txt`, the pattern is expanded to matching files at policy translation time, but Bubblewrap mounts entire directories rather than individual files. This means filesystem access control is at the directory level, not file-pattern level.
- **Example**: A policy allowing `${CWD}/node_modules/**` will mount the entire `node_modules` directory tree, not selectively filter files by pattern.
- **Network filtering**: All-or-nothing network isolation (via `--unshare-net`). Host-specific filtering is not enforced in the initial implementation.

**macOS (Seatbelt)**:
- **Network filtering is limited**: Seatbelt supports network rules in policies, but fine-grained host:port filtering is not consistently enforced across all connection types.
- **Filesystem permissions are precise**: Uses regex-based pattern matching, allowing file-level access control.

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

Use `log(1)` to filter the log file by the log tag or generic `PMG_SBX_` prefix.

```bash
log show --last 5m --predicate 'message ENDSWITH "PMG_SBX_"' --style compact
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

- https://github.com/anthropic-experimental/sandbox-runtime
- https://geminicli.com/docs/cli/sandbox/
- https://github.com/containers/bubblewrap