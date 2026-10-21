# PMG Sandbox Profiles

This directory contains built-in sandbox policies for PMG package managers.

## Available Profiles

### npm-restrictive

Restrictive policy for the npm ecosystem (npm, pnpm, yarn, bun).

### pypi-restrictive

Restrictive policy for the PyPI ecosystem (pip, pip3, pipx, poetry, uv, uvx).

### Package manager leaf profiles

Each package manager maps to a leaf profile that inherits one of the bases above and adds its
own environment variables and paths: `npm`, `npx`, `pnpx`, `pnpm`, `yarn`, `bun`, `aube`,
`aubx`, `pip`, `pipx`, `poetry`, `uv`, `uvx`. The `pnpx` leaf inherits `npx` and adds the corepack
cache. See [docs/sandbox.md](../../docs/sandbox.md#what-the-built-in-profiles-allow-and-deny).

### go

Policy for the Go module ecosystem (go). Standalone profile: Go has a single
package manager, so there is no shared base to inherit from.

### exec

Base profile for `pmg sandbox exec`. `exec` is a reserved workload name, not a
package manager. See [sandbox-exec.md](../../docs/sandbox-exec.md).

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
