# PMG GitHub Action

Install PMG in a Linux GitHub Actions runner and transparently wrap every
subsequent `npm install`, `pip install`, `poetry add`, etc. so malicious
packages are blocked before they execute.

```yaml
- uses: safedep/pmg@v1
```

That's it. Out of the box you get:

- malware blocking against [SafeDep's real-time threat intelligence](https://docs.safedep.io/cloud/malware-analysis)
- a 5-day dependency cooldown (blocks freshly-published versions)
- proxy-based interception of npm/pip/pnpm/yarn/bun/poetry/uv/npx/pnpx

## Quick start

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - uses: safedep/pmg@v1
      - run: npm ci
```

**Order matters.** Put `safedep/pmg` **after** `setup-node` / `setup-python`
/ etc. Each step that writes to `GITHUB_PATH` prepends to `PATH`, and PMG
needs its shims (`$HOME/.pmg/bin/{npm,pip,...}`) to land in front of the
real toolchains.

## Inputs

All toggle inputs default to empty. When empty, the action emits no
`PMG_*` env var for that key and PMG's own defaults apply — so a YAML
loaded via `config-file` is never silently shadowed. Set an input
explicitly to override.

| Input | Effect when set | PMG default if empty |
|---|---|---|
| `version` | PMG release tag (e.g. `v0.42.0`) or `latest` | `latest` |
| `api-key` | SafeDep Cloud API key. Set together with `tenant-id`; mask with a secret | unset (cloud sync disabled) |
| `tenant-id` | SafeDep Cloud tenant ID | unset |
| `endpoint-id` | Reported to SafeDep Cloud as the "machine" identifier | `github-actions/<owner>/<repo>` when cloud is enabled |
| `paranoid` | `PMG_PARANOID` | `false` |
| `cooldown-enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` | `true` |
| `cooldown-days` | `PMG_DEPENDENCY_COOLDOWN_DAYS` | `5` |
| `proxy-mode` | `PMG_PROXY_ENABLED`. Set `false` for guard-based analysis | `true` |
| `sandbox` | `PMG_SANDBOX_ENABLED`. Also relaxes AppArmor user-ns restrictions on the runner | `false` |
| `sandbox-driver` | `PMG_SANDBOX_DRIVER` — `landlock` or `bubblewrap` | `landlock` when sandbox is enabled |
| `verbosity` | `PMG_VERBOSITY` — `silent`, `normal`, or `verbose` | `normal` |
| `disable-telemetry` | `PMG_DISABLE_TELEMETRY` | `false` |
| `skip-event-logging` | `PMG_SKIP_EVENT_LOGGING` | `false` |
| `config-file` | Path to a YAML file in the repo. Copied to PMG's config dir before setup so you can override any config key | unset |
| `cache` | Reuse a previously-extracted PMG binary from `$RUNNER_TOOL_CACHE`. On cache hit, the cached tarball is re-verified against `checksums.txt` fetched from upstream every run | `false` (fresh download per run) |

## Outputs

| Output | Description |
|---|---|
| `version` | The resolved PMG version that was installed. |
| `bin-dir` | Directory containing the `pmg` binary on this runner. |

## Recipes

### Send audit events to SafeDep Cloud

```yaml
- uses: safedep/pmg@v1
  with:
    api-key:   ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id: ${{ secrets.SAFEDEP_TENANT_ID }}
- run: npm ci
# At the end of the job, flush events to SafeDep Cloud.
- run: pmg cloud sync --timeout 60s
  if: always()
```

Why the explicit sync step? Composite actions don't have a clean post-step
hook today. A single trailing step (`if: always()`) keeps everything
visible in your workflow file.

The `endpoint-id` defaults to `github-actions/${{ github.repository }}` so
every workflow on the same repo appears as one endpoint in the SafeDep
Cloud UI. Override it for per-environment splits:

```yaml
- uses: safedep/pmg@v1
  with:
    api-key:     ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id:   ${{ secrets.SAFEDEP_TENANT_ID }}
    endpoint-id: github-actions/${{ github.repository }}/prod
```

### Custom configuration via `config-file`

```yaml
# .github/pmg.yml — pinned in the repo
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

The file is copied into `~/.config/safedep/pmg/config.yml` before
`pmg setup install` runs. PMG merges any missing template keys into it, so
you only need to specify what you want to override.

### Sandbox mode

```yaml
- uses: safedep/pmg@v1
  with:
    sandbox: true
    sandbox-driver: landlock   # or "bubblewrap"
- run: npm ci
```

The action will `systemctl stop apparmor` and clear
`kernel.apparmor_restrict_unprivileged_userns` so unprivileged user
namespaces work. This mutates the runner — only enable when you actually
need install-script containment.

### Setting arbitrary `PMG_*` env vars

Any PMG config key can be overridden via a `PMG_*` env var without an
action input. Set it on the job or the install step:

```yaml
- uses: safedep/pmg@v1
- run: npm ci
  env:
    PMG_TRANSITIVE_DEPTH: 10
```

See [docs/config.md](./config.md) for the full mapping.

## Platform support

| Runner | Supported |
|---|---|
| `ubuntu-latest`, `ubuntu-24.04`, `ubuntu-22.04` (x86_64 + arm64) | Yes |
| `macos-*` | No (fail fast) |
| `windows-*` | No (fail fast) |

macOS and Windows runners are tracked in
[issue #248](https://github.com/safedep/pmg/issues/248).
