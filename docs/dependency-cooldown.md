# Dependency Cooldown

Dependency cooldown filters package versions published within a configurable time window out of registry metadata responses during version resolution. This reduces exposure to supply chain attacks by ensuring the package manager normally only resolves versions that have been available for a minimum number of days.

## How It Works

When cooldown is enabled, PMG intercepts package metadata responses from the registry and strips versions published within the cooldown window. If the requested version range allows an older eligible release, the resolver falls back to it automatically. If no eligible version satisfies the request, the install fails.

Cooldown is enforced through metadata filtering and does not apply to direct tarball installs or workflows that already have a resolved tarball URL (e.g., lockfile or cache scenarios).

## How PMG Reports Cooldown

PMG reports cooldown in the install summary in three ways:

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

## Configuration

Dependency cooldown is configured in `config.yml`. See [config template](../config/config.template.yml) for the full schema. If you don't have a `config.yml` file, create one by running `pmg setup install`.

```yaml
dependency_cooldown:
  enabled: true
  days: 5
```

To show an org-specific message whenever PMG blocks an installation (cooldown
or otherwise), see the top-level `advisory_message` in the
[config template](../config/config.template.yml).

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
```

The skip list is a **per-control exemption**: packages on it **skip only the
cooldown window — they are still analyzed for malware.** Use it when you want a
package to bypass cooldown but still go through every other security control.

If you want a package to bypass **every** control PMG enforces — malware
analysis, dependency cooldown, and any future policies — add it to the
top-level [`trusted_packages`](trusted-packages.md) list instead. A globally
trusted package is automatically exempted from the cooldown window without
needing a separate entry here.

| List | Waives malware analysis | Waives cooldown | Waives future controls |
| --- | --- | --- | --- |
| `trusted_packages` (top level) | yes | yes | yes |
| `dependency_cooldown.skip` | no | yes | no |

Matching:

- A PURL **without a version** skips cooldown for **all versions** of the package.
- A PURL **with a version** skips cooldown for **that version only** (the version
  stays installable; other recent versions are still held).

PyPI names are matched in their normalized form (lowercase, `_`/`.` → `-`).

To skip cooldown for a single command instead of configuring a package
permanently, use the CLI override below.

## CLI Override

Use `--skip-dependency-cooldown` to disable cooldown enforcement for a single invocation without changing the config file:

```bash
pmg --skip-dependency-cooldown npm install express
```

## Requirements

Dependency cooldown is supported for npm and PyPI packages.

## Limitations

### PyPI: requires pip 22.3+ or a PEP 691-capable client

PyPI cooldown is enforced by filtering the [PEP 691 JSON Simple API](https://peps.python.org/pep-0691/) response, which includes a per-file `upload-time` field needed to determine when each version was published. This JSON format is only supported by pip 22.3+ (released October 2022) and other modern tools such as uv, Poetry, and PDM.

Older pip versions request the HTML Simple API, which carries no publish timestamps. PMG cannot apply cooldown filtering to HTML responses and fails open; the request passes through unchanged and the client receives the full version list. Old pip gets no cooldown protection but does not break.
