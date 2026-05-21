# PMG MDM Scripts (macOS)

Deploy and remove [PMG](https://github.com/safedep/pmg) on macOS fleets through an MDM (Jamf, Mosyle, Kandji, Intune).

| File | Purpose |
|------|---------|
| `pmg_setup_install_macos.sh` | Install the binary and configure every user (config, aliases, shims, optional cloud sync) |
| `pmg_uninstall_macos.sh` | Remove per-user state, Keychain credentials, and the binary |
| `lib_macos.sh` | Shared helpers. Deploy it alongside the other two. |
| `config.yml` *(optional)* | When present in the package, the install script deploys it as the machine-wide globally managed config |

The install and uninstall scripts source `./lib_macos.sh` from their own directory, so ship all three together. Zip the `mdm/` folder as the MDM payload. Add a `config.yml` to the folder to deploy a globally managed config (see below).

## Execution model

PMG writes two kinds of state, and the scripts handle each:

- **Machine scope**: the `pmg` binary (`/usr/local/bin` or Homebrew). Needs root.
- **User scope**: config (`~/Library/Application Support/safedep/pmg`), aliases (`~/.pmg.rc` and shell rc edits), PATH shims (`~/.pmg/bin`), and login Keychain credentials. Runs as the user. Keychain also needs the user's GUI session.

The scripts detect how the MDM invoked them:

- **As root** (typical MDM): the script installs or removes the binary machine-wide, then runs the per-user steps for every local human account (UID ≥ 500 with a home under `/Users`), each in its own context via `sudo -u`. Keychain steps run in the logged-in user's session via `launchctl asuser`.
- **As the logged-in user** (an MDM "run as current user" payload, or a person running it by hand): the per-user steps cover that user, and machine-scope steps elevate with `sudo`.

Homebrew can't run as root, so the script runs brew commands as the owner of the Homebrew install.

## Install

```sh
# Binary + per-user setup, no cloud sync
sudo ./pmg_setup_install_macos.sh

# Also enable SafeDep Cloud sync (stores credentials in the logged-in user's Keychain)
sudo SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... ./pmg_setup_install_macos.sh
```

The install script:

1. Installs or updates `pmg` (Homebrew if present, otherwise the GitHub release tarball with SHA-256 verification).
2. If the package includes a `config.yml`, installs it as the globally managed config (see below).
3. Runs `pmg setup install` for each target user to create aliases and shims (and a per-user config, unless a globally managed config is active).
4. With `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` set, enables cloud sync and stores credentials in the logged-in user's Keychain. It skips users who aren't logged in, since there's no session to write to. Run `pmg cloud login` in their session once they log in.

## Uninstall

```sh
sudo ./pmg_uninstall_macos.sh
```

For each target user, the uninstall script:

1. Runs `pmg setup remove` to strip shell aliases and PATH shims.
2. Deletes the config directory, cache directory, `~/.pmg`, `~/.pmg.rc`, and `~/.local/bin/pmg`.
3. Runs `pmg cloud logout` to clear Keychain credentials for the logged-in user. Other users' credentials clear on their next login.

It then removes the machine-wide binary via `brew uninstall`, or by deleting `/usr/local/bin/pmg` and `/opt/homebrew/bin/pmg`. It also removes the globally managed config if present (set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it).

## Globally managed config

Include a `config.yml` next to the scripts to centrally manage PMG configuration. When that file is present at `/Library/Application Support/safedep/pmg/config.yml`, PMG treats it as authoritative and **ignores every user's own config**. `pmg config set` and `pmg config edit` refuse, and the file is root-owned (`0644`), so it is not user-writable.

- By default the global config is an overridable baseline: users can still override its values at runtime with `PMG_*` env vars and CLI flags. Set `global_lockdown: true` in the bundled `config.yml` to forbid those overrides. See [Globally Managed Configuration](../../docs/config.md#globally-managed-configuration) for the full behaviour.
- The file can be **partial**. Keys it does not set fall back to PMG's built-in defaults, not to user values.
- To enable cloud sync, set `cloud.enabled: true` in the bundled `config.yml`. The install script skips the per-user `pmg config set` (a managed config refuses it) but still stores each logged-in user's credentials in the Keychain.
- Install copies the bundled `config.yml` to the global path *before* configuring users, so each user's setup skips writing a per-user config.
- Re-deploying the package overwrites the global config, keeping it in sync with the package.
- Uninstall removes the global config whenever it is present, regardless of whether the uninstall package ships a `config.yml`. Set `PMG_KEEP_GLOBAL_CONFIG=1` to keep it.

Only the config *file* is global. Per-user runtime state (logs, cloud sync database, sandbox profiles) stays under each user's `~/Library`.

## Environment variables

| Variable | Effect |
|----------|--------|
| `SAFEDEP_API_KEY` | SafeDep Cloud API key (install only; with the tenant ID, enables cloud sync) |
| `SAFEDEP_TENANT_ID` | SafeDep Cloud tenant ID (install only) |
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

## Limitations

- The scripts can't read or write the Keychain for a user who isn't logged in, since no session exists to reach. They report and skip those users; configure them in their session when they log in. After an uninstall, their credentials clear on next login.
- Machine-scope steps under a non-root invocation need `sudo`. Without passwordless sudo in a non-interactive context, they fail with an error instead of hanging.
- macOS only. The scripts exit on other platforms.

## Development

```sh
# From this directory
shellcheck -x lib_macos.sh pmg_setup_install_macos.sh pmg_uninstall_macos.sh
```
