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


**Limitation**

- `config set` can only update keys that are present and uncommented in the config file.
If a key is commented out (e.g. `# endpoint_id: "my-machine"`) or missing entirely, `set` will
return a "key not found" error. To fix this, uncomment or add the key manually via `pmg config edit`,
or run `pmg setup install` to merge missing template keys into your config.
