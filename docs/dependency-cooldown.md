# Dependency Cooldown

Dependency cooldown filters package versions published within a configurable time window out of registry metadata responses during version resolution. This reduces exposure to supply chain attacks by ensuring the package manager normally only resolves versions that have been available for a minimum number of days.

## How It Works

When cooldown is enabled, PMG intercepts package metadata responses from the registry and strips versions published within the cooldown window. If the requested version range allows an older eligible release, the resolver falls back to it automatically. If no eligible version satisfies the request, the install fails.

Cooldown is enforced through metadata filtering and does not apply to direct tarball installs or workflows that already have a resolved tarball URL (e.g., lockfile or cache scenarios).

## Configuration

Dependency cooldown is configured in `config.yml`. See [config template](../config/config.template.yml) for the full schema. If you don't have a `config.yml` file, create one by running `pmg setup install`.

```yaml
dependency_cooldown:
  enabled: true
  days: 5
```

## CLI Override

Use `--skip-dependency-cooldown` to disable cooldown enforcement for a single invocation without changing the config file:

```bash
pmg --skip-dependency-cooldown npm install express
```

## Requirements

Dependency cooldown requires [proxy mode](proxy-mode.md) to be enabled. It is supported for npm and PyPI packages.

## Limitations

### PyPI: requires pip 22.3+ or a PEP 691-capable client

PyPI cooldown is enforced by filtering the [PEP 691 JSON Simple API](https://peps.python.org/pep-0691/) response, which includes a per-file `upload-time` field needed to determine when each version was published. This JSON format is only supported by pip 22.3+ (released October 2022) and other modern tools such as uv, Poetry, and PDM.

Older pip versions request the HTML Simple API, which carries no publish timestamps. PMG cannot apply cooldown filtering to HTML responses and fails open; the request passes through unchanged and the client receives the full version list. Old pip gets no cooldown protection but does not break.
