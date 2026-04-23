# Configuration

PMG supports local configuration through a configuration file. To create the default configuration file, run:

```bash
pmg setup install
```

To see the configuration file path and activated configuration, run:

```bash
pmg setup info
```

See [config template](../config/config.template.yml) for the configuration schema.

## Environment Variables

Any configuration key can be overridden using environment variables, without modifying the config file. This is useful for CI/CD pipelines or temporary overrides.

**Format:** `PMG_<KEY>` where the key is the config key uppercased, with nested keys joined by `_`.

| Config key | Environment variable |
|---|---|
| `transitive` | `PMG_TRANSITIVE` |
| `paranoid` | `PMG_PARANOID` |
| `proxy_mode` | `PMG_PROXY_MODE` |
| `proxy_install_only` | `PMG_PROXY_INSTALL_ONLY` |
| `verbosity` | `PMG_VERBOSITY` |
| `skip_event_logging` | `PMG_SKIP_EVENT_LOGGING` |
| `sandbox.enabled` | `PMG_SANDBOX_ENABLED` |
| `dependency_cooldown.enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` |
| `cloud.enabled` | `PMG_CLOUD_ENABLED` |

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