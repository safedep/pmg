# PMG MDM Scripts (macOS)

Deploy and remove [PMG](https://github.com/safedep/pmg) on macOS fleets through an MDM (Jamf, Mosyle, Kandji, Intune).

| File | Purpose |
| --- | --- |
| `pmg_setup_install_macos.sh` | Install the binary and configure every user (config, aliases, shims, optional cloud sync) |
| `pmg_uninstall_macos.sh` | Remove per-user state, active GUI user credentials, and the binary |
| `lib_macos.sh` | Shared helpers. Deploy it alongside the other two. |
| `standalone/pmg_setup_install_macos_standalone.sh` | Generated installer for single-script MDM policies |
| `standalone/pmg_uninstall_macos_standalone.sh` | Generated uninstaller for single-script MDM policies |
| `generate_standalone_scripts.sh` | Regenerates standalone scripts and optionally embeds `config.yml` and cloud credentials |
| `config.yml` *(optional)* | When present in the package, the install script deploys it as the machine-wide globally managed config |

For a multi-file MDM deployment, install `lib_macos.sh` and both entry scripts as sibling files at a fixed path. Add an optional sibling `config.yml` for globally managed config.

For an MDM policy that accepts only one script, use the generated scripts in `standalone/`. Do not upload `lib_macos.sh` separately.

## Execution model

PMG writes two kinds of state, and the scripts handle each:

- **Machine scope**: the `pmg` binary (`/usr/local/bin` or Homebrew). Needs root.
- **User scope**: The config, `pmg.rc`, and shims are under `~/Library/Application Support/safedep/pmg`. The cache is under `~/Library/Caches/safedep/pmg`. Shell rc edits and login Keychain credentials are also user state. Keychain access needs the user's GUI session.

The scripts detect how the MDM invoked them:

- **As root** (typical MDM): the script installs or removes the binary machine-wide, then runs the per-user steps for every local human account (UID ≥ 500 with a home under `/Users`), each in its own context via `sudo -u`. Keychain steps run in the logged-in user's session via `launchctl asuser`.
- **As the logged-in user** (an MDM "run as current user" payload, or a person running it by hand): the per-user steps cover that user, and machine-scope steps elevate with `sudo`.

Homebrew can't run as root, so the script runs brew commands as the owner of the Homebrew install.

## Install

```sh
# Install PMG without cloud credentials
sudo ./pmg_setup_install_macos.sh
```

The install script:

1. Installs or updates `pmg` (Homebrew if present, otherwise the GitHub release tarball with SHA-256 verification).
2. If the package includes a `config.yml`, installs it as the globally managed config (see below).
3. Runs `pmg setup install` for each target user to create aliases and shims (and a per-user config, unless a globally managed config is active).
4. If both cloud variables are set, configures cloud sync for the active GUI user.

Without a managed config, cloud setup runs `pmg config set cloud.enabled true`. It then stores credentials in the user's Keychain.

The installer reports and skips cloud setup for users without an active GUI session. This skip is nonfatal. A cloud login failure is also nonfatal.

## Uninstall

```sh
sudo ./pmg_uninstall_macos.sh
```

For each target user, the uninstall script:

1. Runs `pmg setup remove` to strip shell aliases and PATH shims.
2. Deletes the config directory, cache directory, and legacy PMG paths.
3. Runs `pmg cloud logout` to clear Keychain credentials for the active GUI user.

Credentials for inactive users remain in their Keychains. For full credential cleanup, have each user run `pmg cloud logout` before the uninstall policy removes PMG.

It then removes the machine-wide binary via `brew uninstall`, or by deleting `/usr/local/bin/pmg` and `/opt/homebrew/bin/pmg`. It also removes the globally managed config if present (set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it).

## Globally managed config

Include a `config.yml` next to the scripts to centrally manage PMG configuration. When that file is present at `/Library/Application Support/safedep/pmg/config.yml`, PMG treats it as authoritative and **ignores every user's own config**. `pmg config set` and `pmg config edit` refuse, and the file is root-owned (`0644`), so it is not user-writable.

- By default the global config is an overridable baseline: users can still override its values at runtime with `PMG_*` env vars and CLI flags. Set `global_lockdown: true` in the bundled `config.yml` to forbid those overrides. See [Globally Managed Configuration](../../docs/config.md#globally-managed-configuration) for the full behaviour.
- The file can be **partial**. Keys it does not set fall back to PMG's built-in defaults, not to user values.
- To enable cloud sync, set `cloud.enabled: true` in the bundled `config.yml`. The installer skips the refused per-user config change. It still stores credentials for the active GUI user.
- Install copies the bundled `config.yml` to the global path *before* configuring users, so each user's setup skips writing a per-user config.
- Re-deploying the package overwrites the global config, keeping it in sync with the package.
- Uninstall removes the global config whenever it is present, regardless of whether the uninstall package ships a `config.yml`. Set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it.

Only the config *file* is global. Per-user runtime state (logs, cloud sync database, sandbox profiles) stays under each user's `~/Library`.

## Environment variables

The installer consumes `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` at runtime. The generator consumes them only with `--embed-cloud-credentials`.

| Variable | Effect |
| --- | --- |
| `SAFEDEP_API_KEY` | SafeDep Cloud API key, set with the tenant ID |
| `SAFEDEP_TENANT_ID` | SafeDep Cloud tenant ID, set with the API key |
| `PMG_CONFIG_DIR` | Override the config directory location (uninstall cleanup honors it) |
| `PMG_CACHE_DIR` | Override the cache directory location (uninstall cleanup honors it) |
| `PMG_KEEP_GLOBAL_CONFIG` | Uninstall only: when set, keep the globally managed config instead of removing it |

## Standalone scripts for Microsoft Intune

Microsoft Intune accepts one shell script per policy. Follow Microsoft's [macOS shell-script procedure](https://learn.microsoft.com/en-us/intune/device-management/tools/run-shell-scripts-macos).

The generator writes exactly two files to the output directory:

- `pmg_setup_install_macos_standalone.sh`
- `pmg_uninstall_macos_standalone.sh`

Each file must be smaller than 1 MB for Intune. The generator rejects larger files.

The committed files in [`standalone/`](standalone/) are generic and secret-free. They contain no tenant config or cloud credentials.

### PMG only

From `scripts/mdm/`, generate the installer and uninstaller:

```sh
./generate_standalone_scripts.sh \
  --output-dir /path/to/pmg-intune
```

### Config only

Generate both scripts with the managed config in the installer:

```sh
./generate_standalone_scripts.sh \
  --config /path/to/config.yml \
  --output-dir /path/to/pmg-intune
```

The uninstaller never contains the embedded config.

### Security warning for cloud credentials

**Warning:** Base64 is not encryption. Intune administrators and device administrators can recover credentials from the uploaded installer.

Before you generate a credential installer:

1. Generate the tenant artifacts outside a tracked source directory.
2. Restrict access to the output directory and its files.
3. Use a scoped and revocable API key.
4. Never commit the generated tenant artifacts.
5. Upload both scripts, then remove the local tenant artifacts when you no longer need them.
6. Rotate the API key if you suspect exposure.

Removing the local artifact does not remove Intune's uploaded copy.

### Credentials only

Use Bash for these steps. Read the API key without terminal echo or a literal shell-history value:

```bash
read -rsp 'SafeDep API key: ' safedep_api_key
printf '\n'
read -rp 'SafeDep tenant ID: ' safedep_tenant_id
tenant_output=$(mktemp -d "${TMPDIR:-/tmp}/pmg-intune-credentials.XXXXXX")

SAFEDEP_API_KEY="$safedep_api_key" \
SAFEDEP_TENANT_ID="$safedep_tenant_id" \
  ./generate_standalone_scripts.sh \
  --embed-cloud-credentials \
  --output-dir "$tenant_output"

unset safedep_api_key safedep_tenant_id
printf 'Artifacts: %s\n' "$tenant_output"
```

The installer uses `pmg config set cloud.enabled true` in the active GUI user's config. It then stores the credentials in the Keychain.

### Config plus credentials

First, set cloud sync in the managed `config.yml`:

```yaml
cloud:
  enabled: true
```

Then use Bash to generate both scripts:

```bash
read -rsp 'SafeDep API key: ' safedep_api_key
printf '\n'
read -rp 'SafeDep tenant ID: ' safedep_tenant_id
tenant_output=$(mktemp -d "${TMPDIR:-/tmp}/pmg-intune-config-credentials.XXXXXX")

SAFEDEP_API_KEY="$safedep_api_key" \
SAFEDEP_TENANT_ID="$safedep_tenant_id" \
  ./generate_standalone_scripts.sh \
  --config /path/to/config.yml \
  --embed-cloud-credentials \
  --output-dir "$tenant_output"

unset safedep_api_key safedep_tenant_id
printf 'Artifacts: %s\n' "$tenant_output"
```

The managed config is authoritative. The installer cannot enable cloud sync through a per-user config.

For both credential variants, the installer has mode `0700`. The uninstaller has no embedded credentials.

### Upload to Intune

1. Create an install policy in **Devices > By platform > macOS > Manage devices > Scripts > Add**.
2. Upload only `pmg_setup_install_macos_standalone.sh` to the install policy.
3. Verify that the script is smaller than 1 MB.
4. Set **Run script as signed-in user** to **No**. Intune runs the script as root.
5. Select the script frequency intentionally. Use **Not configured** only for a one-time run.
6. Select the retry count intentionally. Use retries only for script failures.
7. Assign the install policy to the required device group.
8. Create a separate uninstall policy.
9. Upload only `pmg_uninstall_macos_standalone.sh` to the uninstall policy.
10. Set **Run script as signed-in user** to **No** for the uninstall policy.
11. Do not assign install and uninstall policies concurrently.

Only the active GUI user can receive Keychain credentials during a run. Use a recurring install frequency to cover later users.

For manual setup of a later user:

- With managed config and `cloud.enabled: true`, run `pmg cloud login`.
- Without managed config, run `pmg config set cloud.enabled true`, then run `pmg cloud login`.

A missing GUI session is a nonfatal skip. A cloud login failure is also nonfatal. Neither condition causes a nonzero exit for Intune retries.

After you upload both credential variant files, remove the local tenant artifacts:

```bash
rm -rf -- "$tenant_output"
unset tenant_output
```

## Jamf example

Build a Jamf package that installs these sibling files under `/Library/Application Support/safedep/pmg-mdm`:

- `lib_macos.sh`
- `pmg_setup_install_macos.sh`
- `pmg_uninstall_macos.sh`
- Optional `config.yml`

Set both entry scripts to mode `0755`. Then invoke the installed entry script from a Jamf policy:

```sh
#!/bin/sh
MDM_DIR="/Library/Application Support/safedep/pmg-mdm"
SAFEDEP_API_KEY="$4" SAFEDEP_TENANT_ID="$5" \
  "$MDM_DIR/pmg_setup_install_macos.sh"
```

`$4` and `$5` are Jamf script parameters. Adjust them to your configuration.

Invoke `"$MDM_DIR/pmg_uninstall_macos.sh"` from a separate uninstall policy.

If the Jamf policy accepts one script, use the standalone workflow instead.

## Limitations

- Installing PMG's MITM CA into the trust store (`pmg setup cert install`) is not supported via MDM on macOS. Adding a trusted root to the login keychain requires interactive authorization from the user's GUI session, which an MDM deployment cannot supply. Have each user run `pmg setup cert install` in their own session when they need it (only needed for tools that ignore the proxy's CA environment variables, such as Go on macOS).
- The scripts can access only the active GUI user's Keychain. Inactive users' credentials remain. Complete their manual logout before the policy removes PMG.
- Machine-scope steps under a non-root invocation need `sudo`. Without passwordless sudo in a non-interactive context, they fail with an error instead of hanging.
- macOS only. The scripts exit on other platforms.

## Development

Run these checks from `scripts/mdm/`:

```sh
bash ./generate_standalone_scripts_test.sh
bash ./pmg_setup_install_macos_test.sh
bash ./generate_standalone_scripts.sh --check
shellcheck -x -P SCRIPTDIR \
  lib_macos.sh \
  pmg_setup_install_macos.sh \
  pmg_uninstall_macos.sh \
  generate_standalone_scripts.sh \
  generate_standalone_scripts_test.sh \
  pmg_setup_install_macos_test.sh \
  standalone_macos_e2e_test.sh \
  standalone/pmg_setup_install_macos_standalone.sh \
  standalone/pmg_uninstall_macos_standalone.sh
```

**Warning:** The standalone end-to-end test removes PMG state and temporarily renames Homebrew binaries.

Run it only on a disposable macOS CI runner with passwordless `sudo`. The script rejects runs without both guards:

```sh
CI=true PMG_MDM_E2E=1 bash ./standalone_macos_e2e_test.sh
```
