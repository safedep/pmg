# Caching

PMG can cache package analysis results across runs to reduce repeat-install
latency. Caching is opt-in and disabled by default.

## Storage

PMG's on-disk caches share a single SQLite database at
`<cache-dir>/localdb/pmg.db`, where `<cache-dir>` follows the platform
convention:

| Platform | Default cache dir |
|----------|-------------------|
| macOS    | `~/Library/Caches/safedep/pmg` |
| Linux    | `$XDG_CACHE_HOME/safedep/pmg` (or `~/.cache/safedep/pmg`) |
| Windows  | `%LOCALAPPDATA%\safedep\pmg` |

Override the location with the `PMG_CACHE_DIR` environment variable. The cache
is local to the machine and safe to delete at any time.

## Malysis analysis cache

Persists **benign** Malysis (malware analysis) verdicts on disk, so a package
version that was already screened is not re-analyzed on every install.

Only benign verdicts are cached, and each entry expires after a TTL. Malicious,
suspicious, and tenant-excluded verdicts are never cached and are always
re-evaluated. Keep the TTL below your `dependency_cooldown` window so newly
published packages remain covered by cooldown if a cached verdict goes stale.

### Enable

In `config.yml`:

```yaml
analysis_cache:
  malysis:
    enabled: true
    ttl: 24h
```

Or from the CLI:

```bash
pmg config set analysis_cache.malysis.enabled true
pmg config set analysis_cache.malysis.ttl 24h
pmg config edit   # open the config file directly
```

- `enabled` (default `false`) — turn the persistent cache on.
- `ttl` (default `24h`) — how long a cached benign verdict is reused, measured
  from when it was fetched. A non-positive value disables persistence.

### Manage

```bash
pmg setup cache status   # show path, enabled state, TTL, and entry count
pmg setup cache clear    # delete all cached verdicts
```
