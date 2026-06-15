# Analysis Cache

PMG screens every package in the resolved dependency graph against the malware
analysis backend. By default this screening cache is **in-memory and per-run**:
it is empty at the start of each `install`, so every install re-screens the whole
graph — even when the package store is warm and nothing changed. For large or
frequently re-installed graphs this dominates wall-clock time.

The persistent analysis cache stores clean verdicts across runs and reuses them,
so a repeat install of an unchanged graph skips the per-package analysis
round-trip.

> **Status:** this page describes the analysis-cache contract and configuration.
> The caching layer is defined as the `analyzer.MalysisCache` interface so it can
> be backed by different stores; a concrete persistent implementation (sqlite)
> lands in a follow-up. Until then, `enabled` is inert.

## How It Works

- The cache is modeled as the `analyzer.MalysisCache` interface — a pluggable
  contract the analyzer layer reads through. A concrete backend (e.g. sqlite) is
  injected by the caller, so the abstraction is decoupled from any single store.
- Persistent verdicts live under the platform **cache** directory (`config.CacheDir()`
  — XDG cache dir on Linux, `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on
  Windows; overridable via `PMG_CACHE_DIR`), not the config directory, since they
  are regenerable.
- **Only clean (`ALLOW`) verdicts are cached.** Suspicious, malicious, and
  tenant-excluded verdicts are never persisted and are always re-evaluated.
- Each entry expires after `ttl`.

## Configuration

Disabled by default. Caching is analyzer-specific, so it is configured per
analyzer under `analysis_cache`; today only the Malysis (malware) analyzer has a
cache. Enable it in `config.yml`:

```yaml
analysis_cache:
  malysis:
    enabled: true
    ttl: 24h
```

- `enabled` — turn the persistent cache on/off.
- `ttl` — how long a cached verdict stays valid (Go duration, e.g. `30m`, `24h`,
  `168h`). A non-positive `ttl` disables persistence (every lookup is a miss),
  making the cache behave like the default in-memory one.

## Security Trade-off

Caching a verdict means trusting it for up to `ttl` without re-checking. A
package version that was clean when first screened but is **later flagged as
malicious** will be served from cache — and therefore allowed — until its entry
expires. `ttl` bounds that exposure window.

Because only `ALLOW` verdicts are cached, a package that is currently flagged is
never cached and is always re-evaluated. Choose `ttl` to balance install speed
against how quickly you want newly-published malware verdicts to take effect. If
in doubt, keep the cache disabled (the default) or use a short `ttl`.

## Requirements

The analysis cache applies to [proxy mode](proxy-mode.md). It is independent of
[dependency cooldown](dependency-cooldown.md): cooldown decides which *versions*
are eligible to install, while the analysis cache remembers malware verdicts for
versions that were already screened.
