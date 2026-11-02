# Dependency Cooldown

Dependency cooldown restricts package versions published within a configured time window.

## How It Works

PMG applies cooldown to registry requests that pass through its proxy.
The enforcement method depends on the ecosystem.

| Ecosystem | Enforcement |
| --- | --- |
| npm | PMG removes recent versions from registry metadata. |
| PyPI | PMG removes recent files from JSON Simple API responses. |
| Go modules | PMG blocks recent module `.zip` downloads with HTTP 403. It does not filter module metadata. |
| Cargo crates | PMG removes recent versions from the sparse index. It also blocks recent `.crate` downloads with HTTP 403. |

For metadata filtering, PMG intercepts package metadata responses from the registry and strips versions published within the cooldown window. If the requested version range allows an older eligible release, the resolver falls back to it automatically. If no eligible version satisfies the request, the install fails.
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

These install-summary reports appear in per-command runs (`pmg npm ...`) at normal or verbose verbosity.
For metadata filtering, PMG reports cooldown in three ways:

- **Block: no version is eligible.** Every version of the package is within the
  cooldown window. The install fails and PMG reports the package as blocked,
  with the version closest to exiting the window.
- **Block: a requested version is withheld.** You pinned a version on the
  command line (for example `pmg npm install pkg@1.2.3`) and that version is
  within the window. The install fails and PMG reports that version as blocked.
- **Hint: versions withheld, eligible versions remain.** Recent versions were
  withheld but older eligible versions survive. The resolver normally falls
  back to an eligible version and the install succeeds with no extra output.
  The install can still fail when something requires exactly a withheld
  version, for example a lockfile entry or a dependency with an exact version
  pin. PMG cannot see that requirement in the metadata, so in this case it
  prints the withheld versions after the package manager error as the likely
  cause of the failure. When more than 3 packages had versions withheld, the
  hint lists package names only; the package manager error above it names the
  exact version it could not find.

Run PMG with `--verbose` to always list the withheld versions in the execution
report, including on successful installs.

A Go or Cargo download block also appears in the execution report.
Silent mode omits cooldown details and the advisory for a cooldown-only block.
Normal insecure output also omits cooldown details.
Use verbose output to diagnose these cases.
These output settings do not disable cooldown enforcement.

The [persistent proxy](persistent-proxy.md) does not print a per-command install summary.
The daemon cannot see versions pinned on a command line.
It never reports a block because a requested version is withheld.
A withheld npm or PyPI version does not increase its blocked count when older eligible versions remain.
The daemon records aggregate audit counts and reports counts at stop.
Restart the daemon after a cooldown configuration change.

## Configuration

Dependency cooldown is configured in `config.yml`. See [config template](../config/config.template.yml) for the full schema. If you don't have a `config.yml` file, create one by running `pmg setup install`.
This example uses a 5-day window.

```yaml
dependency_cooldown:
  enabled: true
  days: 5
```

The default is `enabled: true` with `days: 2`.
You can also set `PMG_DEPENDENCY_COOLDOWN_ENABLED` and `PMG_DEPENDENCY_COOLDOWN_DAYS` when [lockdown](config.md#lockdown) is inactive.

To show an org-specific message whenever PMG blocks an installation (cooldown
or otherwise), see the top-level `advisory_message` in the
[config template](../config/config.template.yml).
Silent mode does not show it for a cooldown-only block.

## Exempting Specific Packages

Some packages — typically first-party or internal — need to be installed as soon
as they are published (for example, to sanity-test a freshly released version)
and cannot wait out the cooldown window. List them under the
`dependency_cooldown.skip` list:

```yaml
dependency_cooldown:
  enabled: true
  days: 5
  skip:
    - purl: pkg:npm/my-internal-sdk             # all versions
      reason: "First-party SDK; sanity-tested immediately on release"
    - purl: pkg:npm/another-internal-pkg@1.2.3  # only this version
      reason: "Pin a specific just-published build"
    - purl: pkg:golang/example.com/team/module@v1.2.3
      reason: Approved Go release
    - purl: pkg:cargo/internal-crate@0.4.0
      reason: Approved Cargo release
```

The skip list is a **per-control exemption**: packages on it **skip only the
cooldown window — they are still analyzed for malware.** Use it when you want a
package to bypass cooldown but still go through every other security control.
The top-level [`trusted_packages`](trusted-packages.md) list waives malware analysis and cooldown.
Neither list changes sandbox or proxy network policy.

| List | Waives malware analysis | Waives cooldown |
| --- | --- | --- |
| `trusted_packages` (top level) | yes | yes |
| `dependency_cooldown.skip` | no | yes |

Matching:

- A PURL **without a version** skips cooldown for **all versions** of the package.
- A PURL **with a version** skips cooldown for **that version only** (the version
  stays installable; other recent versions are still held).

PyPI names are matched in their normalized form (lowercase, `_`/`.` → `-`).
Cargo names use lowercase.
Go module paths are case-sensitive.
Use the ecosystem's actual version spelling, including the `v` prefix for Go.
Version entries match versions, not version ranges.
See [PURL matching](trusted-packages.md) for ecosystem rules.
An invalid PURL never matches.
Cooldown remains active for the intended package.

PMG records `dependency_cooldown` events for cooldown blocks.
It records `dependency_cooldown_skipped` when a version-specific skip exempts a version inside the active window.
Whole-package skips do not produce a per-version skip audit trail.

## CLI Override

Use `--skip-dependency-cooldown` to disable cooldown enforcement for a single invocation without changing the config file:

```bash
pmg --skip-dependency-cooldown npm install express
```

Insecure installation mode (`PMG_INSECURE_INSTALLATION`) does not waive cooldown.
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
PMG does not follow a redirect of an authenticated publish-time lookup.
Cooldown is then not enforced for that download.
Malware analysis can still run when cooldown cannot determine the package age.

### PyPI: requires pip 22.2+ or a PEP 691-capable client

PMG filters the [PEP 691 JSON Simple API](https://peps.python.org/pep-0691/).
[pip 22.2](https://pip.pypa.io/en/stable/news/#v22-2) added support for this format in July 2022.
PMG reads the optional per-file `upload-time` field added by [PEP 700](https://peps.python.org/pep-0700/) in Simple API version 1.1.
A JSON response without that field does not provide cooldown protection for those files.

Older pip versions request the HTML Simple API, which carries no publish timestamps. PMG cannot apply cooldown filtering to HTML responses and fails open; the request passes through unchanged and the client receives the full version list. Old pip gets no cooldown protection but does not break.
The current warning says to upgrade to pip 22.3+.
pip 22.2 already supports the required JSON format.
