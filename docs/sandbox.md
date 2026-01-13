# Sandbox

Design goal for sandbox in PMG context is to protect against unknown supply chain attacks using principle of least privilege.
We do not want to re-invent sandbox and likely rely on OS native sandbox primitives. This is at the cost of developer experience,
where we have to work within the limitations of the sandbox implementations that we use.

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

Find the log tag in the log file and use it to investigate the sandbox policy violation.

```bash
grep "PMG_SBX_" /tmp/pmg-debug.log
```

Use `log(1)` to filter the log file by the log tag or generic `PMG_SBX_` prefix.

```bash
log show --last 5m --predicate 'message ENDSWITH "PMG_SBX_"' --style compact
```

## References

- https://github.com/anthropic-experimental/sandbox-runtime
- https://geminicli.com/docs/cli/sandbox/
- https://github.com/containers/bubblewrap