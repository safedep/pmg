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

Deploy `lib_macos.sh` in the same directory as the entry scripts. They source it at runtime and fail without it.

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

## Jamf example

Upload the `mdm/` folder as a script payload, or a package that drops the three files together, then invoke the entry script. Jamf runs scripts as root, which covers fleet-wide, multi-user deployment:

```sh
#!/bin/sh
cd "$(dirname "$0")"
SAFEDEP_API_KEY="$4" SAFEDEP_TENANT_ID="$5" ./pmg_setup_install_macos.sh
```

`$4` and `$5` are Jamf script parameters. Adjust them to your configuration.

## JumpCloud example

Deploy PMG with a JumpCloud Command. JumpCloud runs Commands as root, which covers fleet-wide, multi-user deployment.

### Install

1. In the JumpCloud Admin Console, create a new **Command** and set **Run As** to `root`.
2. Upload `lib_macos.sh` and `pmg_setup_install_macos.sh` from `scripts/mdm/`. Optionally upload `config.yml` to deploy a globally managed config. Set the **File Destination** to `/tmp/pmg-mdm/` for each file.
3. Set **Timeout After** to at least 900 seconds so installs on slow networks aren't killed mid-run.
4. To enable cloud sync, define the Command Variables `safedep_api_key` and `safedep_tenant_id`, and mark the API key as a Secret variable.
5. Set the Command body to:

   ```sh
   #!/bin/sh
   set -eu
   cd /tmp/pmg-mdm
   chmod +x pmg_setup_install_macos.sh
   SAFEDEP_API_KEY={{safedep_api_key}} SAFEDEP_TENANT_ID={{safedep_tenant_id}} ./pmg_setup_install_macos.sh
   cd / && rm -rf /tmp/pmg-mdm
   ```

   Drop the `SAFEDEP_API_KEY`/`SAFEDEP_TENANT_ID` variables if cloud sync isn't enabled.
6. Assign the Command to a device group and run it.

### Uninstall

1. Create a second Command as above, uploading `lib_macos.sh` and `pmg_uninstall_macos.sh` instead.
2. Set the Command body to:

   ```sh
   #!/bin/sh
   set -eu
   cd /tmp/pmg-mdm
   chmod +x pmg_uninstall_macos.sh
   ./pmg_uninstall_macos.sh
   cd / && rm -rf /tmp/pmg-mdm
   ```

3. Assign the Command to the same device group and run it.

## Standalone scripts (single-script MDM policies)

Some MDMs accept only one shell script per policy, so use the prebuilt single-file scripts in [`standalone/`](standalone/):

- `pmg_setup_install_macos_standalone.sh`
- `pmg_uninstall_macos_standalone.sh`

They contain no tenant config or cloud credentials, and are smaller than 1 MB (Intune's limit).

### Config only

Regenerate the installer with the managed config embedded:

```sh
./generate_standalone_scripts.sh \
  --config /path/to/config.yml \
  --output-dir /path/to/pmg-intune
```

The uninstaller never contains the embedded config.

### Cloud credentials

Single-script MDMs (like Intune) have no script parameters, so cloud credentials must be embedded at generation time. The generator reads them from the `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` environment variables. Set them however you manage secrets (shell, CI, secrets manager):

```sh
SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... \
  ./generate_standalone_scripts.sh \
  --embed-cloud-credentials \
  --output-dir /path/to/pmg-intune
```

With a managed config, add `--config /path/to/config.yml` (with `cloud.enabled: true` in it) to the same command.

**Warning:** Base64 is not encryption. Anyone who can read the uploaded installer in Intune (Intune admins, device admins) can recover the credentials. Use a scoped and revocable API key, and never commit the generated artifacts.

The credential installer has mode `0700`. The uninstaller has no embedded credentials.

### Intune example

Create two shell-script policies ([Microsoft's procedure](https://learn.microsoft.com/en-us/intune/device-management/tools/run-shell-scripts-macos)):

1. **Install policy**: upload `pmg_setup_install_macos_standalone.sh`, set **Run script as signed-in user** to **No**.
2. **Uninstall policy**: upload `pmg_uninstall_macos_standalone.sh`, same setting.
3. Assign to the device group. Do not assign both policies concurrently.

Only the active GUI user can receive Keychain credentials during a run. Use a recurring install frequency to cover later users. A missing GUI session or a cloud login failure is a nonfatal skip, so neither causes a nonzero exit for Intune retries.

## Limitations

- The scripts run `brew trust --cask safedep/tap/pmg` before brew operations. Homebrew 6+ refuses to load items from untrusted taps, and versioned casks like `pmg@edge` cannot self-trust through a fully qualified install. The trust is item-scoped, not whole-tap.
- Installing PMG's MITM CA into the trust store (`pmg setup cert install`) is not supported via MDM on macOS. Adding a trusted root to the login keychain requires interactive authorization from the user's GUI session, which an MDM deployment cannot supply. Have each user run `pmg setup cert install` in their own session when they need it (only needed for tools that ignore the proxy's CA environment variables, such as Go on macOS).
- The scripts can access only the active GUI user's Keychain. Inactive users' credentials remain. Complete their manual logout before the policy removes PMG.
- Machine-scope steps under a non-root invocation need `sudo`. Without passwordless sudo in a non-interactive context, they fail with an error instead of hanging.
- macOS only. The scripts exit on other platforms.

## Development

Run these checks from `scripts/mdm/`:

```sh
bash ./generate_standalone_scripts_test.sh
bash ./pmg_setup_install_macos_test.sh
bash ./non_macos_guard_test.sh
bash ./generate_standalone_scripts.sh --check
shellcheck -x -P SCRIPTDIR \
  lib_macos.sh \
  e2e_lib_macos.sh \
  pmg_setup_install_macos.sh \
  pmg_uninstall_macos.sh \
  generate_standalone_scripts.sh \
  generate_standalone_scripts_test.sh \
  pmg_setup_install_macos_test.sh \
  non_macos_guard_test.sh \
  standalone_macos_e2e_test.sh \
  multifile_macos_e2e_test.sh \
  standalone/pmg_setup_install_macos_standalone.sh \
  standalone/pmg_uninstall_macos_standalone.sh
```

`non_macos_guard_test.sh` verifies that the scripts refuse to run on a non-macOS host. It skips on macOS.

**Warning:** The end-to-end tests remove PMG state. The standalone test temporarily renames Homebrew binaries. The multifile test creates and deletes a local user account.

Run them only on a disposable macOS CI runner with passwordless `sudo`. Both scripts reject runs without both guards:

```sh
CI=true PMG_MDM_E2E=1 bash ./standalone_macos_e2e_test.sh
CI=true PMG_MDM_E2E=1 bash ./multifile_macos_e2e_test.sh
```

The end-to-end tests do not reach SafeDep Cloud. They use dummy credentials. A `pmg` wrapper on PATH intercepts every `cloud` call, records `cloud login` and `cloud logout`, and fails the test on any other cloud call. Shared test helpers live in `e2e_lib_macos.sh`.
