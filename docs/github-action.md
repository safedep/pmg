# PMG GitHub Action

The PMG GitHub Action installs PMG on a Linux GitHub Actions runner. PMG
then wraps package manager commands such as `npm install`, `pip install`,
or `poetry add`. The proxy blocks malicious packages before they run.

```yaml
- uses: safedep/pmg@v1
```

> **Commit SHA pinning.** The examples use the `v1` tag for readability. Pin
> the action to a full commit SHA. This improves supply chain security. See the
> [GitHub security hardening guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions).

Out of the box the action gives:

- Malware blocking that uses the [SafeDep real-time threat intelligence](https://docs.safedep.io/cloud/malware-analysis).
- A dependency cooldown. This blocks package versions published within the last 5 days.
- Proxy-based interception of [supported package managers](../README.md#supported-package-managers).

## Quick start

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - uses: safedep/pmg@v1
      - run: npm ci
```

**Use the correct step order.** Put `safedep/pmg` after `setup-node` or
`setup-python`. Each of these steps prepends to `PATH`. PMG must put its
shims in front of the real toolchain shims on `PATH`. Run
`pmg setup info --json`. The `user_shims.dir` value shows the PMG shim
directory.

This step order also works when releases change the shim location. Pre-v2
releases put shims in one directory. Newer releases put them under the XDG
data directory. The action adds whichever directory the install creates.

## Inputs

Each toggle input defaults to empty. When an input is empty, the action
sets no `PMG_*` environment variable. PMG then uses its own default for
that key. This behavior prevents the action from silently overriding a
YAML file loaded through `config-file`. Set an input to override the
default.

| Input | Effect when set | PMG default if empty |
|---|---|---|
| `version` | PMG release tag (for example `v0.42.0`) or `latest` | `latest` |
| `api-key` | SafeDep Cloud API key. Set it with `tenant-id`. Use a secret to hold the value. | unset (cloud sync disabled) |
| `tenant-id` | SafeDep Cloud tenant ID | unset |
| `endpoint-id` | Identifier that SafeDep Cloud reports as the machine name | `github-actions/<owner>/<repo>` when cloud is enabled |
| `paranoid` | `PMG_PARANOID` | `false` |
| `cooldown-enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` | `true` |
| `cooldown-days` | `PMG_DEPENDENCY_COOLDOWN_DAYS` | `5` |
| `proxy-mode` | Removed. Proxy interception cannot be disabled. The value `false` stops the action. Other values cause a warning and are ignored. | unset |
| `sandbox` | `PMG_SANDBOX_ENABLED`. Also relaxes AppArmor user namespace limits on the runner | `false` |
| `sandbox-driver` | `PMG_SANDBOX_DRIVER`. Use `landlock` or `bubblewrap` | `landlock` when sandbox is enabled |
| `verbosity` | `PMG_VERBOSITY`. Use `silent`, `normal`, or `verbose` | `normal` |
| `disable-telemetry` | `PMG_DISABLE_TELEMETRY` | `false` |
| `skip-event-logging` | `PMG_SKIP_EVENT_LOGGING` | `false` |
| `config-file` | Path to a YAML file in the repository. The action copies it to the PMG config directory before setup. Use it to override any config key. | unset |
| `cache` | Reuse a previously extracted PMG binary from `$RUNNER_TOOL_CACHE`. On a cache hit the action fetches `checksums.txt` from upstream and verifies the cached tarball again. | `false` (download each run) |

## Outputs

| Output | Description |
|---|---|
| `version` | The PMG version that the action installed. |
| `bin-dir` | The directory that contains the `pmg` binary on this runner. |

## Recipes

### Send audit events to SafeDep Cloud

```yaml
- uses: safedep/pmg@v1
  with:
    api-key:   ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id: ${{ secrets.SAFEDEP_TENANT_ID }}
- run: npm ci
# Flush events at the end of the job.
- run: pmg cloud sync --timeout 60s
  if: always()
```

Why the sync step? Composite actions have no clean post-step hook. A
trailing step with `if: always()` keeps the upload visible in the
workflow file.

The `endpoint-id` defaults to `github-actions/${{ github.repository }}`.
Each workflow on the same repository appears as one endpoint in the
SafeDep Cloud UI. Override it for per-environment splits:

```yaml
- uses: safedep/pmg@v1
  with:
    api-key:     ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id:   ${{ secrets.SAFEDEP_TENANT_ID }}
    endpoint-id: github-actions/${{ github.repository }}/prod
```

### Use `config-file` for custom settings

```yaml
# .github/pmg.yml
paranoid: true
dependency_cooldown:
  enabled: true
  days: 14
trusted_packages:
  - purl: pkg:npm/@my-org/internal-pkg
    reason: "Internal package, signed by build pipeline"
```

```yaml
- uses: safedep/pmg@v1
  with:
    config-file: .github/pmg.yml
```

The action copies the file to `~/.config/safedep/pmg/config.yml` before
`pmg setup install` runs. PMG merges any missing template keys into the
file. Specify only the keys to override.

### Sandbox mode

```yaml
- uses: safedep/pmg@v1
  with:
    sandbox: true
    sandbox-driver: landlock   # or "bubblewrap"
- run: npm ci
```

The action runs `systemctl stop apparmor` and clears
`kernel.apparmor_restrict_unprivileged_userns`. This lets unprivileged
user namespaces work. The change modifies the runner. Enable it only when
you need install-script containment.

### Set `PMG_*` environment variables directly

You can override any PMG config key with a `PMG_*` environment variable.
Set it on the job or on the install step:

```yaml
- uses: safedep/pmg@v1
- run: npm ci
  env:
    PMG_DEPENDENCY_COOLDOWN_DAYS: 10
```

See [docs/config.md](./config.md) for the full mapping.

## Platform support

| Runner | Supported |
|---|---|
| `ubuntu-latest`, `ubuntu-24.04`, `ubuntu-22.04` (x86_64 and arm64) | Yes |
| `macos-*` | No. The action stops. |
| `windows-*` | No. The action stops. |

[Issue #248](https://github.com/safedep/pmg/issues/248) tracks macOS and
Windows runner support.
