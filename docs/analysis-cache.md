# Analysis Cache

PMG screens every package in the resolved dependency graph against the malware
analysis backend. By default this screening cache is **in-memory and per-run**:
it is empty at the start of each `install`, so every install re-screens the whole
graph — even when the package store is warm and nothing changed. For large or
frequently re-installed graphs this dominates wall-clock time.

The persistent analysis cache stores clean verdicts on disk and reuses them
across runs, so a repeat install of an unchanged graph skips the per-package
analysis round-trip.

## How It Works

- Verdicts are cached under `<config-dir>/analysis-cache/`, one record per
  package version, written atomically.
- On lookup, PMG checks the in-memory tier first, then the on-disk tier; a disk
  hit repopulates the in-memory tier for the rest of the run.
- **Only clean (`ALLOW`) verdicts are cached.** Suspicious, malicious, and
  tenant-excluded verdicts are never persisted and are always re-evaluated.
- Each record carries a timestamp and expires after `ttl`.

## Configuration

Disabled by default. Enable it in `config.yml`:

```yaml
analysis_cache:
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
