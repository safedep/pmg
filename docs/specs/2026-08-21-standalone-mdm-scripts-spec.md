# Standalone MDM Scripts

## Context

Some MDM platforms accept or prefer one shell script per policy. The generated scripts are therefore useful beyond Microsoft Intune and must not use vendor-specific implementation names.

## Decision

Use `standalone` as the vendor-neutral term:

- `scripts/mdm/generate_standalone_scripts.sh`
- `scripts/mdm/generate_standalone_scripts_test.sh`
- `scripts/mdm/standalone/pmg_setup_install_macos.sh`
- `scripts/mdm/standalone/pmg_uninstall_macos.sh`

The generator interface and generated script behavior remain unchanged. The default output directory becomes `standalone/`. Status messages, temporary paths, generated-file warnings, tests, and CI step names use “standalone MDM scripts.”

The old Intune-specific generator names and `intune/` directory are removed without compatibility wrappers because this work has not been released. The existing generic vendor-list comment in `lib_macos.sh` remains unchanged.

## Documentation

General README guidance describes standalone MDM scripts. The Microsoft Intune section remains as a vendor-specific deployment example and references the standalone artifacts. Intune-specific names are allowed in documentation examples, including a customized output directory such as `pmg-intune`.

## CI and tests

Tests continue to cover deterministic generation, standalone syntax and permissions, source inlining, config embedding, invalid config handling, source-overwrite protection, and drift detection.

CI invokes the renamed generator and test, checks the committed `standalone/` artifacts, and runs ShellCheck on the source, generator, test, and generated scripts.

Verification must confirm:

- The renamed test fails before the generator rename and passes afterward.
- `generate_standalone_scripts.sh --check` reports current artifacts.
- Generated outputs remain byte-for-byte equivalent except for the generalized generated-file warning.
- No Intune-specific implementation paths, filenames, messages, CI labels, or generated warnings remain.
- The three MDM source scripts remain behaviorally unchanged.

