# Blocked Packages

`pmg` allows you to block a package outright, independent of malware analysis
verdicts. A blocked package is always blocked — it is never downloaded, never
analyzed, and never installable through PMG. Use this list for packages your
organization has banned: deprecated internally, known-bad, or policy-violating.

The blocklist wins over [trusted packages](trusted-packages.md): a package that
appears on both lists is blocked. Only insecure installation mode
(`PMG_INSECURE_INSTALLATION=true`), which bypasses every PMG control, bypasses
the blocklist.

## Configuration

Blocked packages are configured in the `config.yml` file. See [config template](../config/config.template.yml) for the configuration schema.
If you don't have a `config.yml` file, you can create one by running `pmg setup install`.

### Example

```yaml
blocked_packages:
  - purl: pkg:npm/left-pad
    reason: "Deprecated internally; use String.prototype.padStart"
  - purl: pkg:npm/lodash@4.17.20
    reason: "CVE-2021-23337 - upgrade to >=4.17.21"
```

## Matching

Matching mirrors `trusted_packages`:

- A PURL **without** a version blocks **all** versions of the package.
- A PURL **with** a version blocks only that version.

The `reason` is shown to the user whenever the package is blocked, so make it
actionable — say what to use instead, or where to ask for an exception.

## Behaviour

- Blocking is a hard block: there is no interactive confirmation prompt.
- In proxy mode, the block happens before any malware analysis, so blocklisted
  packages never generate analysis traffic.
- If a version range resolves to a blocked version, the install fails with the
  block message; PMG does not steer the package manager to another version.
- Every blocklist block is recorded in the audit event log as a
  `package_blocklist_blocked` event, and synced to SafeDep Cloud when
  [cloud sync](../README.md) is enabled.
