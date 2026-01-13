# Sandbox

Design goal for sandbox in PMG context is to protect against unknown supply chain attacks using principle of least privilege.
We do not want to re-invent sandbox and likely rely on OS native sandbox primitives. This is at the cost of developer experience,
where we have to work within the limitations of the sandbox implementations that we use.

## Policy

PMG defines its own policy model. The design goal is simplicity and ease of use. Sandbox implementations are expected to translate
the policy model into their own native policy format. Rules for policy are:

- Deny by default unless explicitly allowed
- Deny rules have higher priority than allow rules
- Policy profile allows binding package managers to a specific sandbox policy
- Package manager must have a sandbox profile when sandbox is enabled
- Package manager specific sandbox profile may be disabled to skip sandbox for the package manager

## Threat Model

- Policy files are trusted
- Policy enforcement is a sandbox implementation concern
- YAML to sandbox specific policy translation must not make the policy weaker than the original policy
- Variable interpolation in policy files must consider only trusted sources

## Enforcement

The sandbox implementation currently only support `block` mode. This means, any policy violation will block the execution of the
package manager command.

## References

- https://github.com/anthropic-experimental/sandbox-runtime
- https://geminicli.com/docs/cli/sandbox/
- https://github.com/containers/bubblewrap