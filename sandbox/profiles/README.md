# PMG Sandbox Profiles

This directory contains built-in sandbox policies for PMG package managers.

## Available Profiles

### npm-restrictive

Restrictive policy for the npm ecosystem (npm, pnpm, yarn, bun).

### pypi-restrictive

Restrictive policy for the PyPI ecosystem (pip, pip3, pipx, poetry, uv, uvx).

### go

Policy for the Go module ecosystem (go). Standalone profile: Go has a single
package manager, so there is no shared base to inherit from.

### exec

Base profile for `pmg sandbox exec`. `exec` is a reserved workload name, not a
package manager. See [sandbox-exec.md](../../docs/sandbox-exec.md).

### github-actions

Network base for the persistent PMG proxy on a GitHub Actions runner. It allows
the hosts of the runner, its agents, GitHub releases, the GitHub container
registry, and the cache and artifact storage. The storage rules name each
GitHub storage account, not every Azure storage account. Run
`pmg sandbox profile show github-actions` to see them. Its `*:*` deny rule
matches every other host. Under `network-mode: enforce` the proxy refuses
such a host, and under `audit` it records the host. The profile has no
filesystem rules. An action that downloads from another host needs a rule
in the child profile. A proposal from a run in GitHub Actions inherits this
profile. See [github-action.md](../../docs/github-action.md).

## Custom Policies

You can create custom sandbox policies by:

1. Copying one of the built-in profiles
2. Modifying the rules to suit your needs
3. Referencing the custom profile in your PMG config:

```yaml
sandbox:
  enabled: true
  policies:
    npm:
      enabled: true
      profile: /path/to/custom-npm-policy.yml
```

## Policy Schema

See the [Policy Schema Documentation](../policy.go) for details on the YAML structure.

### Supported Variables

- `${HOME}`: User home directory
- `${CWD}`: Current working directory
- `${TMPDIR}`: Temporary directory

## Policy Enforcement

All policy violations will block execution. This provides defense-in-depth protection against malicious install scripts and supply chain attacks.
