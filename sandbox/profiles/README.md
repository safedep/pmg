# PMG Sandbox Profiles

This directory contains built-in sandbox policies for PMG package managers.

## Available Profiles

### npm-restrictive

Restrictive policy for the npm ecosystem (npm, pnpm, yarn, bun).

### pypi-restrictive

Restrictive policy for the PyPI ecosystem (pip, pip3, poetry, uv).

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

### Violation Modes

- `block`: Block execution on policy violation (recommended)
- `warn`: Log warning but allow execution
- `allow`: Allow all operations (disables sandbox)
