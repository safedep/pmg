# Analysis Cache

PMG analyzes package artifacts that a package manager downloads through its proxy.
An install served entirely from the package manager's local cache triggers no analysis.
Trusted packages also skip analysis. See [Proxy Mode](proxy-mode.md).

PMG keeps analysis results in memory for one command.
The persistent proxy keeps them for the lifetime of the daemon.
The optional SQLite cache reuses benign verdicts across processes.

## How It Works

- The cache is modeled as the `analyzer.MalysisCache` interface — a pluggable
  contract the analyzer layer reads through. A concrete backend (e.g. sqlite) is
  injected by the caller, so the abstraction is decoupled from any single store.
- Persistent verdicts live in the SQLite file `<cache-dir>/localdb/pmg.db`.
  See [Storage](caching.md#storage) for platform paths and `PMG_CACHE_DIR`.
- **Only clean (`ALLOW`) verdicts are cached.** Suspicious, malicious, and
  tenant-excluded verdicts are never persisted.
- Each entry expires `ttl` after PMG stores it. A cache hit does not extend it.
- If PMG cannot open or read the cache, it uses live analysis.
  A failed cache write does not stop the install.
  See [Manage](caching.md#manage) for status, clear, and debug output.

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

- `enabled` (default `false`): turn the persistent cache on or off. Disabling it
  keeps the stored verdicts.
- `ttl` (default `24h`): how long a cached verdict stays valid. Use a Go duration,
  for example `30m`, `24h`, or `168h`. A non-positive `ttl` disables persistence.

See [Enable](caching.md#enable) for CLI commands, TTL syntax, and daemon restarts.

## Security Trade-off

A disk-cache hit skips the analysis backend until the entry expires.
If the backend flags that version later, PMG can still allow the cached version.
Keep the cache off or choose a short TTL when fresh verdicts matter most.
To drop all cached verdicts now, run `pmg setup cache clear`.
A process that can write the cache can plant a benign verdict. See [Storage](caching.md#storage).

The persistent proxy also keeps every successful analysis result in memory until it stops.
The `analysis_cache` settings and `pmg setup cache clear` do not change that memory.
See [Manage](caching.md#manage) for the steps after a malware advisory.

## Relation to Dependency Cooldown

The analysis cache is independent of
[dependency cooldown](dependency-cooldown.md): cooldown decides which *versions*
are eligible to install, while the analysis cache remembers malware verdicts for
versions that were already screened.

Keep `ttl` below `dependency_cooldown.days`. The defaults are `24h` and 2 days.
This is guidance, not a guarantee. Cooldown has exemptions and limits that
depend on the ecosystem.
