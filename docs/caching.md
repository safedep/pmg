# Caching

PMG can reuse malware-analysis results to reduce repeat network queries.
The persistent disk cache is opt-in and off by default.
Every proxy also has an in-memory cache for its own lifetime.

## Storage

The analysis cache uses the SQLite file `<cache-dir>/localdb/pmg.db`.

| Platform | Default cache directory |
|---|---|
| macOS | `~/Library/Caches/safedep/pmg` |
| Linux | `$XDG_CACHE_HOME/safedep/pmg`, or `~/.cache/safedep/pmg` |
| Windows | `%LOCALAPPDATA%\safedep\pmg` |

`PMG_CACHE_DIR` replaces the whole cache root. PMG adds no `safedep/pmg` suffix.
Keep this directory on a local disk. Do not use an NFS or SMB share.

The directory also holds `proxy-state.json`, `proxy.log`, and `sandbox/violations/`.
Deleting it can erase the state of a running proxy and its violation reports.
To remove verdicts only, use `pmg setup cache clear`.
Before manual removal of `localdb/`, stop all PMG processes that use it.
Remove the database and its `-wal` and `-shm` siblings together.

A process with write access to the database can plant a benign verdict.
PMG does not authenticate stored rows or separate their keys by tenant.
Do not share the cache between users or restore it from an untrusted CI cache.
The built-in exec profile permits writes to the default cache directories.

## Malysis analysis cache

The disk cache stores only benign `ALLOW` results.
PMG does not persist malicious, suspicious, or tenant-excluded results.
A disk-cache hit skips the backend query for that package version.
If the backend flags it later, PMG can allow the old cached verdict until it expires.
See [Analysis Cache](analysis-cache.md#security-trade-off) for this trade-off.

A short TTL limits reuse from disk. Keep it below `dependency_cooldown.days`.
This is guidance, not a guarantee of fresh analysis when cooldown ends.
For npm and PyPI, lockfile and direct-artifact installs can bypass metadata cooldown.
Go and Cargo also check cooldown on downloaded artifacts before the cache lookup.
See [Dependency Cooldown](dependency-cooldown.md).

The persistent proxy keeps every successful analysis result in memory until it stops.
This includes block, suspicious, tenant-excluded, and unknown-package allows.
That cache has no TTL. The `analysis_cache` settings do not control it.
A short disk TTL or a disabled disk cache does not refresh these memory entries.
Restart the daemon to apply a new malware verdict or tenant exclusion.

### Enable

Set the values in the active `config.yml` file.

```yaml
analysis_cache:
  malysis:
    enabled: true
    ttl: 24h
```

You can also use the CLI when the keys already exist in the file.

```bash
pmg config set analysis_cache.malysis.enabled true
pmg config set analysis_cache.malysis.ttl 24h
pmg config edit
```

If a key is missing, add it with `pmg config edit` or merge template keys with `pmg setup install`.
See [Configuration](config.md) for managed files and overrides.

`enabled` defaults to `false`. Disabling it retains the stored entries.
`ttl` defaults to `24h` and counts from storage time, not the last cache hit.
Use a Go duration with a unit, such as `30m`, `24h`, or `168h`.
`7d`, `1w`, and a quoted number without a unit are invalid.
An unquoted YAML integer represents nanoseconds. A nonpositive TTL disables disk reuse.
A duration decode error can make PMG use defaults for the whole configuration.
After an edit, run `pmg setup cache status` and check the reported TTL.

A new process applies the current TTL to existing rows.
A larger TTL can keep an older verdict valid for longer.
A daemon reads these settings only at startup. Restart it after a change.

### Manage

```bash
pmg setup cache status
pmg setup cache clear
```

Status shows the database path, enabled state, TTL, and entry count.
`Entries` includes expired rows. PMG removes an expired row when it looks it up.
No background task prunes the database. A zero count alone does not prove cache failure.

If PMG cannot open or read the cache, it uses live analysis.
A failed write does not fail the install. Normal output omits cache warnings.
Use `--debug` before the package manager name to see hits, misses, and warnings.
Add `--log <file>` to retain debug logs.
Status reports an open failure when the database exists, but does not test future writes.

Clear deletes disk verdicts. It does not clear a running proxy's memory.
After a malware advisory, stop the daemon, clear its disk cache, then start it again.
Preserve its config, cache, and state paths and its start options.
A root daemon uses root's cache. Run `sudo pmg setup cache clear` for that cache.
For a service, stop it before the clear and start it afterward.
On Windows, stop a foreground proxy with Ctrl+C.
See [Persistent Proxy](persistent-proxy.md#commands).
