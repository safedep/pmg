# Trusted Packages

A trusted package skips malware analysis and the [dependency cooldown](dependency-cooldown.md) window.
Trust does not change the sandbox or proxy network policy.
A trusted package's install scripts still run under the active sandbox policy.
Use this list for packages you fully vouch for — typically first-party packages or vendored internal dependencies.
Trust applies only to the downloaded artifact's own identity.
It does not propagate to dependencies.

PMG compares ecosystem, package name, and optional version.
It does not compare the registry origin.
PURL qualifiers and fragments do not constrain trust to an internal registry.
A public artifact with the same identity can receive the exemption.
Use controlled package scopes and narrow version pins to reduce exposure.
They do not create an origin boundary.

If you only want to waive a single control (for example, install a package
immediately without waiting out the cooldown, but still have it analyzed for
malware), use the per-control skip list for that control instead — e.g.
[`dependency_cooldown.skip`](dependency-cooldown.md#exempting-specific-packages).

It is the only per-control skip list in `config.yml`.
Authenticated SafeDep Cloud tenant exclusions can separately allow a flagged version while keeping cooldown active.

## Configuration

Trusted packages are configured in the `config.yml` file. See [config template](../config/config.template.yml) for the configuration schema.
If you don't have a `config.yml` file, you can create one by running `pmg setup install`.

Use `pmg config path` to find the active file and `pmg config edit` to edit YAML sequences.
`pmg config set` does not append list entries.
An accepted [managed config](config.md#globally-managed-configuration) replaces the per-user file.
Per-user trust entries then have no effect.

An explicit list replaces the template list.
The template trusts the npm launcher `@safedep/pmg` without a version.
Use an empty list to remove that default exemption.

```yaml
trusted_packages: []
```

Restart a persistent proxy after adding or removing trust.
Each per-command invocation loads configuration in a new process.

### Example

```yaml
trusted_packages:
  - purl: pkg:npm/@safedep/pmg
    reason: All versions of the PMG npm launcher are trusted
  - purl: pkg:npm/express@4.18.0
    reason: "Version 4.18.0 of Express is a trusted package"
  - purl: pkg:pypi/internal-sdk@1.2.3
    reason: Approved Python version
  - purl: pkg:golang/example.com/team/module@v1.2.3
    reason: Approved Go version
  - purl: pkg:cargo/internal-crate@0.4.0
    reason: Approved Cargo version
```

The launcher entry does not cover PMG's platform-specific optional dependencies.
Those package names receive their own checks.
The wired trust checks support npm, PyPI, Go, and Cargo artifacts.
An accepted PURL of another type does not add a supported ecosystem.

A versionless PURL trusts every version of that exact package.
A versioned PURL matches the ecosystem's version identity, not a range.
PyPI folds names to lowercase and replaces `_` and `.` with `-`.
PyPI version comparison normalizes equivalent version spellings.
Cargo folds names to lowercase.
Go module paths remain case-sensitive.
Use the actual Go version, including its `v` prefix.

Invalid PURLs never match.
Their parse warning can be hidden during initialization.
`pmg config get` displays raw values and does not prove that each PURL parsed.

When event logging is enabled, the artifact trust path records `install_trusted_allowed`.
Cloud sync can translate and deliver that event when configured.
Do not assume every exemption has a retained remote record when logging or delivery is disabled.
