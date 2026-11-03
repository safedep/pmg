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

`config get` shows the value from the config file, the template, or a `PMG_*` override.
It can print a `PMG_*` value as a string. It does not show CLI flags.
`config get --system` reads the managed file and ignores `PMG_*` overrides.

To set a scalar config value:

```bash
pmg config set paranoid true
pmg config set dependency_cooldown.days 10
pmg config set cloud.enabled true
```

See [config template](../config/config.template.yml) for the configuration schema.
PMG ignores unknown keys without a warning. Check spelling and nesting after every edit.
A YAML syntax error or a value that PMG cannot decode can discard the whole file.
PMG then uses a compiled-in fallback and shows no warning.
This can disable configured sandbox or paranoid protection.
The fallback is not the config template.
It trusts no package and has no sandbox policies.
It also ignores most `PMG_*` overrides.
`PMG_INSECURE_INSTALLATION` and `PMG_DISABLE_TELEMETRY` still apply.
[Lockdown](#lockdown) blocks `PMG_INSECURE_INSTALLATION` in all cases.
`pmg config get` prints each key that the file sets. This includes a misspelled key.
After an edit, run it with the key name from the config template and check the value.
If it prints `config not initialized`, PMG could not load the file and uses the compiled-in fallback.
Write durations such as `168h`. `7d` is not valid.

Set custom npm, PyPI, Go, and Cargo endpoints in `proxy.registries`.
Edit this list as YAML with `pmg config edit`.
Registry entries that decode but fail validation cause a fail-closed error.
A wrong YAML shape can fail decoding first and trigger the whole-file fallback above.
An endpoint must be an object such as `- url: https://packages.example.com`, not a plain string.

Invalid registry entries and invalid `sandbox.network_mode` or
`proxy.server.network_mode` values block package-manager, proxy, and sandbox profile commands.
Network modes accept `audit` or `enforce`. An empty value means `audit`.
Package-manager commands, including `pmg npm run`, and `pmg proxy start` refuse to run.
`pmg sandbox exec` and `pmg sandbox profile` commands refuse too.
Repair commands such as `pmg config` and `pmg setup` remain usable.
See [Custom Registries](proxy-mode.md#custom-registries).

## Blocked Packages

`blocked_packages` lists packages that PMG blocks at download, whatever the malware analysis says. A
blocked package wins over `trusted_packages` and over `--insecure-installation`:

```yaml
blocked_packages:
  - purl: pkg:npm/evil                  # a PURL, or a prefix that ends with "/*" or ".*"
    vers: "vers:npm/>=1.2.0|<2.0.0"     # optional. Not with a version in the PURL
    reason: "IR-2291 credential stealer"  # optional. Shown in the block message
```

An entry that does not parse fails closed, as an invalid `proxy.registries` entry does. On a managed
endpoint only the managed config sets the list.

## Cloud Policy

With `cloud.policy: true` inside `cloud.enabled: true`, PMG applies the policy that your security
admin sets in SafeDep Cloud: block entries, trust entries and the dependency cooldown.

```bash
pmg config set cloud.policy true
```

- PMG fetches the policy in the background after a command, at most every 5 minutes, also when
  `cloud.auto_sync.enabled` is false. `pmg cloud sync` fetches it at once.
- PMG keeps the policy in `cloud-policy/` in the config directory. When the fetch fails or you log
  out, PMG keeps the last policy that it applied.
- A block entry of the policy wins over every trust entry, `trusted_packages` and
  `--insecure-installation`. A trust entry never skips the malware analysis and never allows
  verified malware.
- When the policy sets the dependency cooldown, PMG ignores `PMG_DEPENDENCY_COOLDOWN_*` and refuses
  `--skip-dependency-cooldown`.
- Under `global_lockdown: true`, the policy does not change a key that the managed config sets. To
  turn off all cloud content on a managed endpoint, set `cloud.policy: false` in the managed config.
- With `cloud.policy` on, PMG ignores the exclusions of the malware analysis. Create trust entries
  instead.

`pmg setup doctor` and `pmg setup info --json` show the applied revision and the age of the cache.

## Environment Variables

Use environment variables to override scalar values or lists of scalars for one process.
Lists of objects, such as `trusted_packages`, `dependency_cooldown.skip`, and
`proxy.registries`, need YAML. Environment strings cannot represent those object lists.
A decode failure can trigger the whole-file fallback described above.

**Format:** `PMG_<KEY>` where the key is the config key uppercased, with nested keys joined by `_`.

| Config key                    | Environment variable              |
| ----------------------------- | --------------------------------- |
| `paranoid`                    | `PMG_PARANOID`                    |
| `proxy.install_only`          | `PMG_PROXY_INSTALL_ONLY`          |
| `proxy.server.profile` | `PMG_PROXY_SERVER_PROFILE` |
| `proxy.server.network_mode` | `PMG_PROXY_SERVER_NETWORK_MODE` |
| `proxy.server.enforce.enabled` | `PMG_PROXY_SERVER_ENFORCE_ENABLED` |
| `proxy.server.enforce.ports` | `PMG_PROXY_SERVER_ENFORCE_PORTS` (comma-separated) |
| `proxy.server.enforce.eligible_users` | `PMG_PROXY_SERVER_ENFORCE_ELIGIBLE_USERS` (comma-separated) |
| `proxy.server.enforce.exempt_users` | `PMG_PROXY_SERVER_ENFORCE_EXEMPT_USERS` (comma-separated) |
| `proxy.server.enforce.exempt_executables` | `PMG_PROXY_SERVER_ENFORCE_EXEMPT_EXECUTABLES` (comma-separated) |
| `proxy.server.enforce.skip_destinations` | `PMG_PROXY_SERVER_ENFORCE_SKIP_DESTINATIONS` (comma-separated) |
| `proxy.server.enforce.cgroup` | `PMG_PROXY_SERVER_ENFORCE_CGROUP` |
| `proxy.server.enforce.deny_udp` | `PMG_PROXY_SERVER_ENFORCE_DENY_UDP` |
| `proxy.server.enforce.namespaces.mode` | `PMG_PROXY_SERVER_ENFORCE_NAMESPACES_MODE` |
| `verbosity`                   | `PMG_VERBOSITY`                   |
| `skip_event_logging`          | `PMG_SKIP_EVENT_LOGGING`          |
| `sandbox.enabled`             | `PMG_SANDBOX_ENABLED`             |
| `dependency_cooldown.enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` |
| `cloud.enabled`               | `PMG_CLOUD_ENABLED`               |

A variable for a list key replaces the whole list. The `--enforce-*` flags of `pmg proxy start`
add to a list instead. See [persistent-proxy.md](persistent-proxy.md#policy-from-the-command-line).

The legacy flat key `proxy_install_only` is still supported when the `proxy:` section does not exist in the config file.

Proxy interception cannot be disabled.
Package-manager commands refuse `proxy.enabled: false` and `PMG_PROXY_ENABLED=false`.
Legacy `proxy_mode: false` and `PMG_PROXY_MODE=false` cause this error only when the file
has no `proxy:` section. Lockdown ignores these environment overrides.
These checks do not make `pmg config`, `pmg setup`, or `pmg proxy start` reject the same legacy keys.
See [Proxy Mode](proxy-mode.md#removed-disabling-proxy-interception).

**Example:**

```bash
# Enable paranoid mode without editing the config file
PMG_PARANOID=true pmg npm install express

# Skip the proxy for known non-download commands
PMG_PROXY_INSTALL_ONLY=true pmg npm install express
```

Paranoid mode blocks suspicious packages instead of asking for confirmation.
It also blocks registry GET and HEAD requests when an enabled registry parser fails.
It also blocks artifact requests with an incomplete package identity.
See [registry identity policy](proxy-mode.md#how-pmg-identifies-a-package) for exceptions and analyzer-error behavior.

**Precedence (highest to lowest):**

1. CLI flags
2. Environment variables (`PMG_*`)
3. Config file (`config.yml`)
4. Config template

Under a [globally managed config](#globally-managed-configuration) with `global_lockdown` enabled, PMG disables `PMG_*` and managed-flag overrides.

**Limitation**

- `config set` can only update keys that are present and uncommented in the config file.
  If a key is commented out (e.g. `# some_key: value`) or missing entirely, `set` will
  return a "key not found" error. To fix this, uncomment or add the key manually via `pmg config edit`,
  or run `pmg setup install` to merge missing template keys into your config.
- Lists and maps need `config edit`. `config set` updates existing scalar nodes only.
  Boolean values must be `true` or `false`. Integer nodes require integers.
  A string assignment does not validate the setting's semantics before writing it.

## Which file a command reads

`pmg config path` prints the active config file and why PMG chose it:

```
/home/alice/.config/safedep/pmg/config.yml (user)
  ignored by a root daemon: it reads /root/.config/safedep/pmg/config.yml, or /etc/safedep/pmg/config.yml when that exists
```

The source is one of `user`, `root per-user`, `PMG_CONFIG_DIR` or `managed`. A command under
`sudo` reads root's own per-user file, not the file of the user who ran `sudo`, when no managed
file applies and `PMG_CONFIG_DIR` is not set in its environment. A root daemon such as `sudo pmg proxy start --enforce`
therefore does not see edits a user makes with `pmg config edit`. `pmg proxy status` names the
file the daemon loaded.

| Platform | User configuration | Default event logs |
|---|---|---|
| macOS | `~/Library/Application Support/safedep/pmg/config.yml` | The config directory's `logs/` |
| Linux | `$XDG_CONFIG_HOME/safedep/pmg/config.yml`, or `~/.config/safedep/pmg/config.yml` | The config directory's `logs/` |
| Windows | `%APPDATA%\safedep\pmg\config.yml` | `%LOCALAPPDATA%\safedep\pmg\logs` |

`PMG_CONFIG_DIR` replaces the user config directory.
An explicit override also relocates event logs beneath it.
Default Windows event logs use local data rather than roaming configuration.

Sudo can remove cloud credentials and CI or Kubernetes context from the environment.
The managed file can hold settings. It does not replace those credentials or context variables.
Preserve only the variables a root process needs under the host's sudo policy.
For example, `sudo --preserve-env=SAFEDEP_API_KEY,SAFEDEP_TENANT_ID pmg cloud sync`
passes cloud credentials but does not preserve the rest of the invoking user's environment.

To configure a machine-wide baseline for a root daemon, use the managed config. `--system` on `pmg config edit`, `config set`
and `config get` works on it:

```bash
sudo pmg config edit --system
sudo pmg config set --system proxy.server.enforce.deny_udp false
pmg config get --system proxy.server.enforce.ports
```

`edit` and `set` need root and create the file from the template when it is missing, with the
same ownership checks as `pmg setup install --system`.
On Windows, use an administrator terminal and omit `sudo`. `get` works for any user.
Creating this file changes configuration for every account on the machine.
PMG then ignores each user's per-user file.
Use `--system` only for an intended machine-wide baseline. Under `sudo`
without `--system`, `edit` and `set` refuse and name both files, instead of changing root's
per-user config in silence. When a managed config exists, they refuse without `--system` for
every user, and tell root to add the flag.

## Globally Managed Configuration

For centrally managed or fleet deployments, PMG can read an OS-level **global config file**. When this file exists, it is authoritative: PMG uses it and ignores the per-user `config.yml` (the two are never merged). An administrator ships a machine-wide baseline this way, and can lock it (see [Lockdown](#lockdown)) to forbid user overrides.

**Paths** (used when the file is present):

| OS      | Global config path                                    |
| ------- | ----------------------------------------------------- |
| macOS   | `/Library/Application Support/safedep/pmg/config.yml` |
| Linux   | `/etc/safedep/pmg/config.yml`                         |
| Windows | `%PROGRAMDATA%\safedep\pmg\config.yml`                |

Check whether a global config is active with `pmg setup info`:

```bash
pmg setup info
# Config Source: global            <- global config, overrides allowed
# Config Source: global (locked)   <- global config with lockdown enabled
# Config Source: user              <- per-user config in effect
```

### Behavior

Whenever a global config file is present and only the system account can change it:

- **It is authoritative.** PMG ignores the per-user `config.yml`. The file may be **partial**. Keys it does not set fall back to the values in the [config template](../config/config.template.yml), not to a user's values.
- **Profile paths start next to the global file.** A relative `policy_templates` path resolves there.
  A relative `sandbox.policies.<pm>.profile` path tries that directory first.
  Without lockdown, it can fall back to the working directory or a user profile.
  Under lockdown, PMG excludes both user-controlled sources.
- **`config set` and `config edit` fail.** They return an error stating the config is globally managed. To change it, deploy an updated file at the OS path, which is root-owned and not writable by users, or run `sudo pmg config edit --system` (see below).
- **`pmg setup install` skips the per-user config.** It still creates shell aliases and shims per user.

By default a user can still override the global config's values at runtime through `PMG_*` environment variables and CLI flags. Enable lockdown to forbid that.

PMG rejects a managed path that another account can change or that the account cannot reach.
It then uses the per-user file, and lockdown does not apply.
Each command prints a warning. `pmg setup doctor` fails.
On Unix, root must control the file and its path. Sticky ancestors and read-only mounts
have specific exceptions. The two immediate parent directories have stricter checks.
On Windows, Administrators or SYSTEM must own the file and its two parent directories.
See [Configuration permissions](system-install.md#configuration) for the full rules.

### Lockdown

Add `global_lockdown: true` to the global config to enforce it:

```yaml
# Only meaningful in the global config file.
global_lockdown: true
```

Write `global_lockdown` as the YAML boolean `true`.
Quoted `"true"`, `yes`, and `1` do not enable it. PMG shows no warning.
Check the lockdown state with `pmg config path` or `pmg setup info`.

When lockdown is on:

- **CLI flags that would change a managed value fail fast.** For example, `pmg --sandbox=false ...` or `pmg --paranoid ...` errors out instead of overriding policy. Governed flags: `--paranoid`, `--skip-event-log`, `--sandbox`, `--sandbox-enforce`, `--sandbox-profile`, `--sandbox-allow`, `--skip-dependency-cooldown`. Operational flags such as `--dry-run` keep working.
- **Configuration environment overrides do not apply.** This includes `PMG_INSECURE_INSTALLATION`,
  which otherwise bypasses malware blocking. `PMG_SANDBOX_DRIVER` and `PMG_DISABLE_TELEMETRY`
  still apply.
- **Project overlays do not apply.** PMG ignores saved overlays and refuses `pmg sandbox allow`.
- **A sandbox profile resolves from managed locations only.** `sandbox.policies.<pm>.profile` and a parent a profile inherits resolve to a built-in profile, a template of the global config, an absolute path, or a path next to the global config file. PMG does not read the user profile directory, the user preset directory or the working directory, because the user writes them.

Subcommand flags have separate rules. `pmg proxy start` and `pmg sandbox exec` refuse
flags that widen a locked policy. Narrowing rules can still be added.
Operational listen flags such as `--host` and `--port` remain usable.
See [Proxy policy overrides](persistent-proxy.md#network-policy) and
[Exec network rules](sandbox-exec.md#network).

PMG reads `global_lockdown` directly from the global file.
Environment variables and CLI flags cannot change this switch.
If a trusted path's file is unreadable or its YAML cannot be parsed, PMG treats it as locked
and uses the compiled-in fallback. A file that parses but cannot decode uses the compiled-in fallback and retains only the
lockdown state that the YAML boolean selected.
A path that fails the ownership or reachability check is ignored instead, as described above.
Invalid decoded registries and network modes fail closed.
`PMG_CONFIG_DIR` and `PMG_CACHE_DIR` can relocate user state but cannot replace a managed file.

### Precedence

| Mode                                   | Effective order (highest to lowest)                                        |
| -------------------------------------- | -------------------------------------------------------------------------- |
| No global config                       | CLI flags > `PMG_*` env > per-user `config.yml` > config template          |
| Global config, no lockdown             | CLI flags > `PMG_*` env > global config > config template                  |
| Global config, `global_lockdown: true` | global config > config template (env and managed-flag overrides refused)   |

### Deploying via MDM

Scripts to install or update PMG and deploy a global config across a macOS, Linux or Windows fleet (Jamf, Mosyle, Kandji, Intune, JumpCloud) live in [`scripts/mdm`](../scripts/mdm). Bundle a `config.yml` next to the scripts. The installer places it at the global path, and the uninstaller removes it. See the [`scripts/mdm` README](../scripts/mdm/README.md) for details.

## System Install (Linux and Windows)

See [System Install](system-install.md) for system shims, PATH, permissions, and runtime data.

## Endpoint identity

PMG groups its cloud events under an endpoint identity. By default PMG uses the machine identity. Set an explicit identity with `cloud.endpoint_id` (or `PMG_CLOUD_ENDPOINT_ID`). PMG also derives a stable identity in CI and Kubernetes.

A shared fleet baseline should normally leave `cloud.endpoint_id` empty.
Set the same value on many hosts only when you want them to be one endpoint.
To keep hosts separate, leave it empty or set a distinct value on each host.

Precedence (highest to lowest):

1. The configured `cloud.endpoint_id` or `PMG_CLOUD_ENDPOINT_ID`.
2. A hosted CI identity.
3. A Kubernetes identity.
4. The machine identity.

### GitHub Actions

PMG without the action derives `gh:<owner>/<repo>` on hosted GitHub Actions runners.
This is the automatic hosted-CI provider currently supported.
A self-hosted runner keeps machine identity, or gets Kubernetes workload identity in a Pod.
Set an explicit ID for an ephemeral fleet that needs another stable grouping.

The `safedep/pmg` action uses `gha/<owner>/<repo>` when its cloud credential inputs are set.
Its `endpoint-id` input overrides that default, including on self-hosted runners.
That exported value overrides `cloud.endpoint_id` in `config-file` unless lockdown ignores overrides.
Use the action input when configuring this identity. See [GitHub Action](github-action.md).

### Kubernetes

PMG derives a stable identity for each workload, so you do not set `cloud.endpoint_id` per workload. The identity has one of these forms:

- `k8s:<namespace>/<workload>`
- `k8s:<cluster>/<namespace>/<workload>`

PMG detects Kubernetes from `KUBERNETES_SERVICE_HOST`, the service-account namespace file,
or `KUBE_NAMESPACE` together with `KUBE_POD_NAME` or `KUBE_WORKLOAD_NAME`.
The namespace file takes precedence over `KUBE_NAMESPACE`.
Without a namespace, PMG cannot derive a workload ID and keeps machine identity.
Pods without the namespace file must provide `KUBE_NAMESPACE` to retain workload grouping.

The `KUBE_*` variables are a PMG convention, not automatic Kubernetes environment. A platform team injects them through the Downward API for explicit context or a stable workload name.

| Variable             | Purpose                                | Downward API field             |
| -------------------- | -------------------------------------- | ------------------------------ |
| `KUBE_NAMESPACE`     | Namespace                              | `metadata.namespace`           |
| `KUBE_POD_NAME`      | Pod name                               | `metadata.name`                |
| `KUBE_POD_UID`       | Pod UID                                | `metadata.uid`                 |
| `KUBE_WORKLOAD_NAME` | Stable workload name                   | set to the workload name       |
| `KUBE_WORKLOAD_KIND` | Workload kind (for example Deployment) | set to the workload kind       |
| `KUBE_CLUSTER_NAME`  | Cluster name                           | set for a multi-cluster tenant |

```yaml
env:
  - name: KUBE_NAMESPACE
    valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
  - name: KUBE_POD_NAME
    valueFrom: { fieldRef: { fieldPath: metadata.name } }
  - name: KUBE_WORKLOAD_NAME
    value: checkout
```

Set `KUBE_WORKLOAD_NAME` for a stable identity.
Otherwise PMG derives it from `KUBE_POD_NAME`, or from the Pod hostname.
If it cannot recognize a generated controller suffix, it uses the full Pod name
and writes a diagnostic log warning. Normal output does not show that warning.
