# Dependency Cooldown

Dependency cooldown blocks installation of package versions published within a configurable time window. This reduces exposure to supply chain attacks by ensuring only versions that have been available for a minimum number of days can be installed.

## How It Works

When cooldown is enabled, PMG intercepts package metadata responses from the registry and strips versions published within the cooldown window. The package manager's resolver then falls back to the latest eligible version automatically.

If all versions of a package are within the cooldown window, the installation is blocked entirely and PMG reports the earliest version and estimated wait time.

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
pmg npm install --skip-dependency-cooldown express
```

## Requirements

Dependency cooldown requires [proxy mode](proxy-mode.md) to be enabled. It is currently supported for npm packages.
