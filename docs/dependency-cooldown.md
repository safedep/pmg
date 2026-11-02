# Dependency Cooldown

Dependency cooldown restricts package versions published within a configured time window.
PMG enables cooldown by default with a 2-day window.

## How It Works

PMG applies cooldown to registry requests that pass through its proxy.
The enforcement method depends on the ecosystem.

| Ecosystem | Enforcement |
| --- | --- |
| npm | PMG removes recent versions from registry metadata. |
| PyPI | PMG removes recent files from JSON Simple API responses. |
| Go modules | PMG blocks recent module `.zip` downloads with HTTP 403. It does not filter module metadata. |
| Cargo crates | PMG removes recent versions from the sparse index. It also blocks recent `.crate` downloads with HTTP 403. |

For metadata filtering, the resolver can select an older eligible release if the version constraint permits it.
The install fails if no eligible version satisfies the request.
For npm, PMG repairs a withheld `latest` tag with the highest eligible stable version at or below the former `latest`.
PMG removes the tag if no such version exists.
PMG removes other tags that point to withheld versions.
For example, an install of `pkg@next` can fail instead of selecting an older version.

For npm and PyPI, cooldown does not check a direct artifact download.
An install with an already resolved artifact URL can therefore bypass cooldown.
This includes some lockfile workflows.

For Go and Cargo, a lockfile or version pin does not exempt a downloaded artifact.
Go does not select an older version after PMG returns HTTP 403.
Cargo can also fail on a locked version even when an older crate exists.
See the [Go](proxy-mode.md#go-experimental) and [Cargo](proxy-mode.md#cargo-experimental) proxy details.

PMG cannot check packages that the package manager serves from its own cache without a registry request.
Cargo git dependencies also bypass the crate registry handlers.

## How PMG Reports Cooldown

Per-command runs, such as `pmg npm install`, report cooldown at normal or verbose verbosity.
The metadata filtering report has three outcomes.

- **No eligible version.** PMG reports a block with the version closest to leaving the window.
- **Command-line pin withheld.** PMG reports a block when a command-line version pin refers to a withheld version.
- **Eligible versions remain.** The resolver normally selects an eligible version. If the command fails, PMG lists withheld versions as a possible cause. A transitive exact pin can cause this failure. When more than 3 packages have withheld versions, the hint lists package names only.

A Go or Cargo download block also appears in the execution report.
Use `pmg --verbose npm install` to include withheld versions after a successful install.
Silent mode omits cooldown details and the advisory for a cooldown-only block.
Normal insecure output also omits cooldown details.
Use verbose output to diagnose these cases.
These output settings do not disable cooldown enforcement.

The [persistent proxy](persistent-proxy.md) does not print a per-command install summary.
It has no command-line pin map.
A withheld npm or PyPI version does not always increase its blocked count when older eligible versions remain.
The daemon records aggregate audit counts and reports counts at stop.
Restart the daemon after a cooldown configuration change.

## Configuration

Configure cooldown in `config.yml`.
Use `pmg config edit` to edit the file.
See [configuration](config.md) and the [config template](../config/config.template.yml) for the full schema.
This example uses a 5-day window.

```yaml
dependency_cooldown:
  enabled: true
  days: 5
```

The default is `enabled: true` with `days: 2`.
You can also set `PMG_DEPENDENCY_COOLDOWN_ENABLED` and `PMG_DEPENDENCY_COOLDOWN_DAYS` when [lockdown](config.md#lockdown) is inactive.

The top-level `advisory_message` adds an organization message to block reports.
Its display follows the output limits above.

## Exempting Specific Packages

Add packages that need an immediate release to `dependency_cooldown.skip`.
A PURL without a version exempts all versions of that package.
A PURL with a version exempts only that version.

```yaml
dependency_cooldown:
  enabled: true
  days: 5
  skip:
    - purl: pkg:npm/my-internal-sdk
      reason: First-party SDK
    - purl: pkg:npm/another-internal-pkg@1.2.3
      reason: Approved release
    - purl: pkg:golang/example.com/team/module@v1.2.3
      reason: Approved Go release
    - purl: pkg:cargo/internal-crate@0.4.0
      reason: Approved Cargo release
```

Skip entries waive only cooldown.
PMG still analyzes these packages for malware.
The top-level [`trusted_packages`](trusted-packages.md) list waives malware analysis and cooldown.
Neither list changes sandbox or proxy network policy.

| List | Waives malware analysis | Waives cooldown |
| --- | --- | --- |
| `trusted_packages` | yes | yes |
| `dependency_cooldown.skip` | no | yes |

PyPI names use lowercase with `_` and `.` replaced by `-`.
Cargo names use lowercase.
Go module paths are case-sensitive.
Use the ecosystem's actual version spelling, including the `v` prefix for Go.
Version entries match versions, not version ranges.
See [PURL matching](trusted-packages.md) for ecosystem rules.
An invalid PURL never matches.
PMG logs a warning, which can be hidden during initialization.
Cooldown remains active for the intended package.

PMG records `dependency_cooldown` events for cooldown blocks.
It records `dependency_cooldown_skipped` when a version-specific skip exempts a version inside the active window.
Whole-package skips do not produce a per-version skip audit trail.

## CLI Override

Put the root flag before the package manager name to disable cooldown for one command.

```bash
pmg --skip-dependency-cooldown npm install express
```

The insecure flag does not waive cooldown.
When a trusted global config enables [lockdown](config.md#lockdown), PMG rejects the skip flag.

## Requirements

PMG supports cooldown for npm, PyPI, Go modules, and Cargo crates.
Go and Cargo support is experimental.
Custom registries must use [configured and recognized endpoints](proxy-mode.md#custom-registries).

## Limitations

PMG needs a publish timestamp to apply cooldown.
It leaves versions without timestamps eligible.
This applies to npm metadata without `time`, PyPI files without `upload-time`, and Cargo index entries without `pubtime`.
Go and Cargo downloads also proceed when the publish-time lookup fails.
PMG refuses authenticated lookup redirects to another origin.
That refusal can leave cooldown unenforced for the download.
Malware analysis can still run when cooldown cannot determine the package age.

### PyPI requires pip 22.2+ or a PEP 691-capable client

PMG filters the [PEP 691 JSON Simple API](https://peps.python.org/pep-0691/).
[pip 22.2](https://pip.pypa.io/en/stable/news/#v22-2) added support for this format in July 2022.
PMG reads the optional per-file `upload-time` field added by [PEP 700](https://peps.python.org/pep-0700/) in Simple API version 1.1.
A JSON response without that field does not provide cooldown protection for those files.

Older pip clients request HTML responses.
PMG passes these responses through without cooldown filtering.
The current warning says to upgrade to pip 22.3+.
pip 22.2 already supports the required JSON format.
