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

The SQLite implementation stores verdicts in `<cache-dir>/localdb/pmg.db`.
See [Storage](caching.md#storage) for platform paths and `PMG_CACHE_DIR`.

PMG persists only benign `ALLOW` verdicts.
It does not persist suspicious, malicious, or tenant-excluded results.
An entry uses the ecosystem, package name, and version as its key.
The cache does not separate tenants or analysis endpoints.
Do not share it between trust domains.

PMG counts `ttl` from the time it stores a verdict.
A cache hit does not extend that time.
The current `ttl` applies to existing entries when a process opens the cache.
A larger value can keep an old verdict valid for longer.
PMG deletes an expired entry when it looks up that entry.
No background task prunes expired rows.

If PMG cannot open or read the cache, it uses live analysis.
A failed cache write does not fail the install.
Use `pmg --debug <manager> ...` to see hits, misses, and cache warnings.
Use `pmg --debug --log <file> <manager> ...` to retain those diagnostics.
See [Manage](caching.md#manage) for status and clearing commands.

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

- `enabled` — turn the persistent cache on/off. Disabling it retains stored rows.
- `ttl` defaults to `24h`. Use a Go duration such as `30m`, `24h`, or `168h`.
The unit `d` is not valid. A zero or negative TTL disables the disk cache.
Always include a unit. An unquoted YAML integer represents nanoseconds.

You can also run `pmg config set analysis_cache.malysis.enabled true`.
See [Configuration](config.md) for environment overrides and managed configuration.
A duration decode error can make PMG use defaults for the whole configuration.
After a change, run `pmg setup cache status` and check the TTL.

A daemon reads its configuration only at startup.
Restart it after a change. A root daemon uses root's cache directory.
Use `sudo pmg setup cache status` or `sudo pmg setup cache clear` for that cache.
Preserve any explicit config, cache, and state paths when you restart the daemon.

## Security Trade-off

A disk-cache hit skips the analysis backend until the entry expires.
If the backend flags that version later, PMG can still allow the cached version.
Keep the cache off or choose a short TTL when fresh verdicts matter most.
A process that can write the database can plant a benign verdict.
Do not share the directory between users or restore it from an untrusted CI cache.
The built-in exec profile permits writes to the default cache directories.

The daemon's in-memory cache has no TTL or eviction.
It keeps all successful analysis results, including block, suspicious, and unknown-package allows.
The `analysis_cache` settings do not control this memory cache.
A new malware verdict or tenant exclusion might not take effect until a restart.
`pmg setup cache clear` does not clear a running daemon's memory.

After a malware advisory, stop the daemon, clear the disk cache as its user, then restart it.
Use the same state path and start options. On Windows, stop a foreground proxy with Ctrl+C.
See [Persistent Proxy](persistent-proxy.md#commands) for lifecycle details.

## Relation to Dependency Cooldown

Cooldown decides which versions can install. The cache remembers analysis verdicts.
Keep `ttl` shorter than `dependency_cooldown.days` to request a fresh disk-cached verdict
before a new version leaves the cooldown window.
The defaults are `24h` and 2 days.
This does not make cooldown a limit on stale verdicts.
Cooldown has exemptions and ecosystem-specific limits.
See [Dependency Cooldown](dependency-cooldown.md).
