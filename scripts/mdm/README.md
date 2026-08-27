# PMG MDM Scripts

Deploy and remove [PMG](https://github.com/safedep/pmg) on macOS and Linux fleets through an MDM (Jamf, Mosyle, Kandji, Intune, JumpCloud).

## Layout

| Directory | Purpose |
| --- | --- |
| `macos/` | macOS deployment scripts: `lib_macos.sh`, `pmg_setup_install_macos.sh`, `pmg_uninstall_macos.sh` |
| `linux/` | Linux deployment scripts: `lib_linux.sh`, `pmg_setup_install_linux.sh`, `pmg_uninstall_linux.sh` |
| `standalone/` | Generated single-file installers and uninstallers for MDM policies that accept one script |
| `lib/` | Shared engine for the standalone generators and test helpers |
| `tests/` | Test scripts and E2E helpers |
| `generate_standalone_macos.sh` | Regenerates macOS standalone scripts; optionally embeds `config.yml` and cloud credentials |
| `generate_standalone_linux.sh` | Regenerates Linux standalone scripts; optionally embeds `config.yml` and cloud credentials |
| `config.yml` *(optional)* | When present in the package, the install script deploys it as the machine-wide globally managed config |

For a multi-file MDM deployment, install the shared lib and both entry scripts as sibling files at a fixed path. Add an optional sibling `config.yml` for globally managed config.

For an MDM policy that accepts only one script, use the generated scripts in `standalone/`. Do not upload the shared lib separately.

## Execution model

PMG writes two kinds of state, and the scripts handle each:

- **Machine scope**: the `pmg` binary (`/usr/local/bin` on both platforms; Homebrew on macOS). Needs root.
- **User scope**: config, aliases, shims, and credentials are per-user. On macOS they live under `~/Library/Application Support/safedep/pmg` and the login Keychain. On Linux they live under `~/.config/safedep/pmg` and the Secret Service keyring. Credential access needs the user's active session.

The scripts detect how the MDM invoked them:

- **As root** (typical MDM): the script installs or removes the binary machine-wide, then runs the per-user steps for every local human account, each in its own context via `sudo -u`. Credential steps run in the user's session: `launchctl asuser` on macOS, `DBUS_SESSION_BUS_ADDRESS` on Linux.
- **As the logged-in user** (an MDM "run as current user" payload, or a person running it by hand): the per-user steps cover that user, and machine-scope steps elevate with `sudo`.

On macOS, Homebrew can't run as root, so the script runs brew commands as the owner of the Homebrew install. On Linux, the binary always comes from the GitHub release tarball.

## Install

Deploy the shared lib in the same directory as the entry scripts. They source it at runtime and fail without it.

```sh
# Install PMG without cloud credentials
sudo ./pmg_setup_install_macos.sh   # macOS
sudo ./pmg_setup_install_linux.sh   # Linux
```

The install script:

1. Installs or updates `pmg` (Homebrew on macOS if present; otherwise the GitHub release tarball with SHA-256 verification).
2. If the package includes a `config.yml`, installs it as the globally managed config (see below).
3. Runs `pmg setup install` for each target user to create aliases and shims (and a per-user config, unless a globally managed config is active).
4. If both cloud variables are set, enables cloud sync and runs `pmg cloud sync` for each target user.

Without a managed config, cloud setup runs `pmg config set cloud.enabled true`. It stores credentials in the keychain when the user has an active session. It then runs cloud sync with the credentials from the environment.

An inactive session prevents keychain storage. It does not prevent cloud sync. A cloud login or cloud sync failure is nonfatal during installation.

## Cloud sync only

Use `--cloud-sync-only` to skip installation and setup. The script checks for an existing PMG installation and runs `pmg cloud sync` for each target user.

```sh
SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... \
  sudo ./pmg_setup_install_macos.sh --cloud-sync-only

SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... \
  sudo ./pmg_setup_install_linux.sh --cloud-sync-only
```

The standalone installers support the same option. A standalone installer can use credentials embedded by its generator.

The installer finds `--cloud-sync-only` in any argument position and ignores other arguments. This behavior supports MDM-provided arguments such as the three built-in Jamf parameters.

The MDM must pass script arguments or invoke an installer that already exists at a fixed path. A direct standalone upload in Intune, Mosyle, or Kandji cannot select sync-only mode.

The script exits successfully without work when credentials are not configured or PMG is not installed. PMG must have cloud sync enabled in each target user's config or in the managed config. If cloud sync is disabled for a target user, the script returns a nonzero status. Run the normal installer to configure new users, or use a managed config with `cloud.enabled: true`. Each user sync has a one-minute timeout. The script attempts every user and returns a nonzero status if any sync fails.

## Uninstall

```sh
sudo ./pmg_uninstall_macos.sh   # macOS
sudo ./pmg_uninstall_linux.sh   # Linux
```

For each target user, the uninstall script:

1. Runs `pmg setup remove` to strip shell aliases and PATH shims.
2. Deletes the config directory, cache directory, and legacy PMG paths.
3. Runs `pmg cloud logout` to clear keychain credentials for the active session.

Credentials for inactive users remain in their keychains. For full credential cleanup, have each user run `pmg cloud logout` before the uninstall policy removes PMG.

It then removes the machine-wide binary and the globally managed config if present (set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it).

## Globally managed config

Include a `config.yml` next to the scripts to centrally manage PMG configuration. When that file is present at the global path, PMG treats it as authoritative and **ignores every user's own config**. `pmg config set` and `pmg config edit` refuse, and the file is root-owned (`0644`), so it is not user-writable.

| Platform | Global config path |
| --- | --- |
| macOS | `/Library/Application Support/safedep/pmg/config.yml` |
| Linux | `/etc/safedep/pmg/config.yml` |

- By default the global config is an overridable baseline: users can still override its values at runtime with `PMG_*` env vars and CLI flags. Set `global_lockdown: true` in the bundled `config.yml` to forbid those overrides. See [Globally Managed Configuration](../../docs/config.md#globally-managed-configuration) for the full behaviour.
- The file can be **partial**. Keys it does not set fall back to PMG's built-in defaults, not to user values.
- To enable cloud sync, set `cloud.enabled: true` in the bundled `config.yml`. The installer skips the refused per-user config change. It stores credentials for the active session and syncs each target user.
- Install copies the bundled `config.yml` to the global path *before* configuring users, so each user's setup skips writing a per-user config.
- Re-deploying the package overwrites the global config, keeping it in sync with the package.
- Uninstall removes the global config whenever it is present, regardless of whether the uninstall package ships a `config.yml`. Set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it.

Only the config *file* is global. Per-user runtime state (logs, cloud sync database, sandbox profiles) stays under each user's home.

## Environment variables

The installer consumes `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` at runtime. The generators consume them only with `--embed-cloud-credentials`.

| Variable | Effect |
| --- | --- |
| `SAFEDEP_API_KEY` | SafeDep Cloud API key, set with the tenant ID |
| `SAFEDEP_TENANT_ID` | SafeDep Cloud tenant ID, set with the API key |
| `PMG_CONFIG_DIR` | Override the config directory location (uninstall cleanup honors it) |
| `PMG_CACHE_DIR` | Override the cache directory location (uninstall cleanup honors it) |
| `PMG_KEEP_GLOBAL_CONFIG` | Uninstall only: when set, keep the globally managed config instead of removing it |

## Jamf example (macOS)

Upload the `macos/` folder as a script payload, or a package that drops the three files together, then invoke the entry script. Jamf runs scripts as root, which covers fleet-wide, multi-user deployment:

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
2. Upload the shared lib and install script for your platform (`macos/lib_macos.sh` + `macos/pmg_setup_install_macos.sh`, or `linux/lib_linux.sh` + `linux/pmg_setup_install_linux.sh`). Optionally upload `config.yml` to deploy a globally managed config. Set the **File Destination** to `/tmp/pmg-mdm/` for each file.
3. Set **Timeout After** to at least 900 seconds so installs on slow networks aren't killed mid-run.
4. To enable cloud sync, define the Command Variables `safedep_api_key` and `safedep_tenant_id`, and mark the API key as a Secret variable.
5. Set the Command body to:

   ```sh
   #!/bin/sh
   set -eu
   cd /tmp/pmg-mdm
   chmod +x pmg_setup_install_*.sh
   SAFEDEP_API_KEY={{safedep_api_key}} SAFEDEP_TENANT_ID={{safedep_tenant_id}} ./pmg_setup_install_*.sh
   cd / && rm -rf /tmp/pmg-mdm
   ```

   Drop the `SAFEDEP_API_KEY`/`SAFEDEP_TENANT_ID` variables if cloud sync isn't enabled.
6. Assign the Command to a device group and run it.

### Uninstall

1. Create a second Command as above, uploading the shared lib and uninstall script instead.
2. Set the Command body to:

   ```sh
   #!/bin/sh
   set -eu
   cd /tmp/pmg-mdm
   chmod +x pmg_uninstall_*.sh
   ./pmg_uninstall_*.sh
   cd / && rm -rf /tmp/pmg-mdm
   ```

3. Assign the Command to the same device group and run it.

## Standalone scripts (single-script MDM policies)

Some MDMs accept only one shell script per policy, so use the prebuilt single-file scripts in [`standalone/`](standalone/):

- `pmg_setup_install_macos_standalone.sh` / `pmg_uninstall_macos_standalone.sh`
- `pmg_setup_install_linux_standalone.sh` / `pmg_uninstall_linux_standalone.sh`

They contain no tenant config or cloud credentials, and are smaller than 1 MB (Intune's limit).

### Config only

Regenerate the installer with the managed config embedded:

```sh
./generate_standalone_macos.sh \
  --config /path/to/config.yml \
  --output-dir /path/to/pmg-intune

./generate_standalone_linux.sh \
  --config /path/to/config.yml \
  --output-dir /path/to/pmg-intune
```

The uninstaller never contains the embedded config.

### Cloud credentials

Single-script MDMs (like Intune) have no script parameters, so cloud credentials must be embedded at generation time. The generator reads them from the `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` environment variables. Set them however you manage secrets (shell, CI, secrets manager):

```sh
SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... \
  ./generate_standalone_macos.sh \
  --embed-cloud-credentials \
  --output-dir /path/to/pmg-intune
```

With a managed config, add `--config /path/to/config.yml` (with `cloud.enabled: true` in it) to the same command.

**Warning:** Base64 is not encryption. Anyone who can read the uploaded installer in Intune (Intune admins, device admins) can recover the credentials. Use a scoped and revocable API key, and never commit the generated artifacts.

The credential installer has mode `0700`. The uninstaller has no embedded credentials.

### Intune example (macOS)

Create two shell-script policies ([Microsoft's procedure](https://learn.microsoft.com/en-us/intune/device-management/tools/run-shell-scripts-macos)):

1. **Install policy**: upload `pmg_setup_install_macos_standalone.sh`, set **Run script as signed-in user** to **No**.
2. **Uninstall policy**: upload `pmg_uninstall_macos_standalone.sh`, same setting.
3. Assign to the device group. Do not assign both policies concurrently.

Only the active GUI user can receive Keychain credentials during a run. The installer can still sync every target user with its embedded credentials. A missing GUI session, cloud login failure, or cloud sync failure does not cause a nonzero install exit for Intune retries.

### Intune example (Linux)

Intune for Linux supports shell scripts with the same single-script model. Upload the Linux standalone scripts and set the execution context to **root**.

## Limitations

- macOS: the scripts run `brew trust --cask safedep/tap/pmg` before brew operations. Homebrew 6+ refuses to load items from untrusted taps, and versioned casks like `pmg@edge` cannot self-trust through a fully qualified install. The trust is item-scoped, not whole-tap.
- macOS: installing PMG's MITM CA into the trust store (`pmg setup cert install`) is not supported via MDM. Adding a trusted root to the login keychain requires interactive authorization from the user's GUI session, which an MDM deployment cannot supply. Have each user run `pmg setup cert install` in their own session when they need it.
- The scripts can access only the active session's keychain. Inactive users' credentials remain. Complete their manual logout before the policy removes PMG.
- Machine-scope steps under a non-root invocation need `sudo`. Without passwordless sudo in a non-interactive context, they fail with an error instead of hanging.
- Linux: only systemd/logind systems are supported for session detection. Headless servers without a D-Bus session bus skip cloud credential steps.
- Linux: no Homebrew path. The binary always comes from the GitHub release tarball.
- Linux: the install and uninstall fan-out forces each user's `HOME` and clears `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, and `XDG_DATA_HOME`, so per-user state stays under the passwd home (`~/.config`, `~/.cache`) or the `PMG_CONFIG_DIR` and `PMG_CACHE_DIR` overrides. A user who installed pmg in their own shell with a custom `XDG_CONFIG_HOME` keeps state elsewhere. The uninstall does not remove that state. Ask the user to run `pmg setup remove --config-file` in their own session.

## Development

Run these checks from `scripts/mdm/`:

```sh
bash ./tests/generate_standalone_test.sh
bash ./tests/pmg_setup_install_test.sh
bash ./tests/os_guard_test.sh
bash ./generate_standalone_macos.sh --check
bash ./generate_standalone_linux.sh --check
shellcheck -x -P SCRIPTDIR -P lib \
  macos/lib_macos.sh \
  linux/lib_linux.sh \
  macos/pmg_setup_install_macos.sh \
  macos/pmg_uninstall_macos.sh \
  linux/pmg_setup_install_linux.sh \
  linux/pmg_uninstall_linux.sh \
  lib/generate_standalone_lib.sh \
  lib/test_lib.sh \
  generate_standalone_macos.sh \
  generate_standalone_linux.sh \
  tests/generate_standalone_test.sh \
  tests/pmg_setup_install_test.sh \
  tests/os_guard_test.sh \
  tests/e2e_lib_macos.sh \
  tests/e2e_lib_linux.sh \
  tests/standalone_macos_e2e_test.sh \
  tests/standalone_linux_e2e_test.sh \
  tests/multifile_macos_e2e_test.sh \
  tests/multifile_linux_e2e_test.sh \
  standalone/pmg_setup_install_macos_standalone.sh \
  standalone/pmg_uninstall_macos_standalone.sh \
  standalone/pmg_setup_install_linux_standalone.sh \
  standalone/pmg_uninstall_linux_standalone.sh
```

`os_guard_test.sh` verifies that every entry script refuses to run on the wrong OS. It runs the macOS half on Linux and the Linux half on macOS, skipping whichever half matches the host.

**Warning:** The end-to-end tests remove PMG state. The standalone test temporarily renames Homebrew binaries. The multifile test creates and deletes a local user account.

Run them only on a disposable CI runner with passwordless `sudo`. Both scripts reject runs without both guards:

```sh
CI=true PMG_MDM_E2E=1 bash ./tests/standalone_macos_e2e_test.sh
CI=true PMG_MDM_E2E=1 bash ./tests/multifile_macos_e2e_test.sh

CI=true PMG_MDM_E2E=1 bash ./tests/standalone_linux_e2e_test.sh
CI=true PMG_MDM_E2E=1 bash ./tests/multifile_linux_e2e_test.sh
```

The end-to-end tests do not reach SafeDep Cloud. They use dummy credentials. A `pmg` wrapper on PATH intercepts every `cloud` call, records `cloud login` and `cloud logout`, and fails the test on any other cloud call. Shared test helpers live in `tests/e2e_lib_macos.sh` and `tests/e2e_lib_linux.sh`.
