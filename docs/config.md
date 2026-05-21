# Configuration

PMG supports local configuration through a configuration file. To create the default configuration file, run:

```bash
pmg setup install
```

To see the configuration file path and activated configuration, run:

```bash
pmg setup info
```

To edit configuration file:

```bash
pmg config edit
```

To get a config value (output is JSON):

```bash
pmg config get paranoid
pmg config get cloud.enabled
```

To set a config value:

```bash
pmg config set paranoid true
pmg config set transitive_depth 10
pmg config set cloud.enabled true
```
See [config template](../config/config.template.yml) for the configuration schema.

## Environment Variables

Any configuration key can be overridden using environment variables, without modifying the config
file. This is useful for CI/CD pipelines or temporary overrides.

**Format:** `PMG_<KEY>` where the key is the config key uppercased, with nested keys joined by `_`.

| Config key | Environment variable |
|---|---|
| `transitive` | `PMG_TRANSITIVE` |
| `paranoid` | `PMG_PARANOID` |
| `proxy.enabled` | `PMG_PROXY_ENABLED` |
| `proxy.install_only` | `PMG_PROXY_INSTALL_ONLY` |
| `verbosity` | `PMG_VERBOSITY` |
| `skip_event_logging` | `PMG_SKIP_EVENT_LOGGING` |
| `sandbox.enabled` | `PMG_SANDBOX_ENABLED` |
| `dependency_cooldown.enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` |
| `cloud.enabled` | `PMG_CLOUD_ENABLED` |

Legacy environment variables `PMG_PROXY_MODE` and `PMG_PROXY_INSTALL_ONLY` (for the old flat keys) are still supported when the `proxy:` section does not exist in the config file.

**Example:**

```bash
# Enable paranoid mode without editing the config file
PMG_PARANOID=true pmg npm install express

# Restrict proxy to install commands only
PMG_PROXY_INSTALL_ONLY=true pmg npm install express
```

**Precedence (highest to lowest):**

1. CLI flags
2. Environment variables (`PMG_*`)
3. Config file (`config.yml`)
4. Built-in defaults

Under a [globally managed config](#globally-managed-configuration), PMG disables `PMG_*` and managed-flag overrides.


**Limitation**

- `config set` can only update keys that are present and uncommented in the config file.
If a key is commented out (e.g. `# endpoint_id: "my-machine"`) or missing entirely, `set` will
return a "key not found" error. To fix this, uncomment or add the key manually via `pmg config edit`,
or run `pmg setup install` to merge missing template keys into your config.

## Globally Managed Configuration

For centrally managed or fleet deployments, PMG can read an OS-level **global config file**. When this file exists, it is authoritative: PMG uses it and ignores the per-user `config.yml` (the two are never merged). An administrator, or an individual who wants a machine-wide config, can pin configuration that users cannot change.

**Paths** (used when the file is present):

| OS | Global config path |
|---|---|
| macOS | `/Library/Application Support/safedep/pmg/config.yml` |
| Linux | `/etc/safedep/pmg/config.yml` |
| Windows | `%PROGRAMDATA%\safedep\pmg\config.yml` |

Check whether a global config is active with `pmg setup info`:

```bash
pmg setup info
# Config Source: global (managed)   <- global config in effect
# Config Source: user               <- per-user config in effect
```

### Behaviour

- **Authoritative.** When a global file is present, PMG ignores the per-user `config.yml`. The file may be **partial**. Keys it does not set fall back to PMG's built-in defaults, not to a user's values.
- **`config set` and `config edit` fail.** They return an error stating the config is globally managed. To change it, deploy an updated file at the OS path, which is root-owned and not writable by users.
- **`pmg setup install` skips the per-user config** while a global config is active. It still creates shell aliases and shims per user.
- **CLI flags that would change a managed value fail fast.** For example, `pmg --sandbox=false ...` or `pmg --paranoid ...` errors out instead of overriding policy. Governed flags: `--transitive`, `--transitive-depth`, `--include-dev-dependencies`, `--paranoid`, `--skip-event-log`, `--proxy-mode`, `--sandbox`, `--sandbox-enforce`, `--sandbox-profile`, `--sandbox-allow`, `--skip-dependency-cooldown`. Operational flags such as `--dry-run` keep working.
- **`PMG_*` variables cannot change a managed config**, including `PMG_INSECURE_INSTALLATION` (which otherwise bypasses malicious-package blocking). `PMG_CONFIG_DIR` and `PMG_CACHE_DIR` still relocate per-user state directories (logs, cache) but leave the managed config alone.

### Precedence under a managed config

Under a managed config, PMG disables `PMG_*` environment overrides and rejects flags that would change a managed value. The effective order is:

1. Global config file
2. Built-in defaults

### Deploying via MDM (macOS)

Scripts to install or update PMG and deploy a global config across a macOS fleet (Jamf, Mosyle, Kandji, Intune) live in [`scripts/mdm`](../scripts/mdm). Bundle a `config.yml` next to the scripts. The installer places it at the global path, and the uninstaller removes it. See the [`scripts/mdm` README](../scripts/mdm/README.md) for details.
