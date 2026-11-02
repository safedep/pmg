# System Install

Use system install when one machine or image should protect every user account: shared VMs, golden Docker images, MDM fleets, and similar setups. It runs on Linux and Windows.

```bash
sudo pmg setup install --system
```

On Windows, run the same command from a terminal started as administrator:

```powershell
& "$env:ProgramFiles\safedep\pmg\pmg.exe" setup install --system
```

**Requires root on Linux and an administrator on Windows.** Install PMG into a standard system path first: `/usr/local/bin` on Linux, `%ProgramFiles%\safedep\pmg\pmg.exe` on Windows. A user-local build (e.g. `~/go/bin/pmg`, or `pmg.exe` from `npm install -g`) is rejected.

On Windows, the release also ships `pmg_Windows_x86_64.msi`. It installs `pmg.exe` at that path and runs `pmg setup install --system` as SYSTEM. Run it from an elevated prompt, or push it through an MDM:

```powershell
msiexec /i pmg_Windows_x86_64.msi /qn
```

Uninstall from Apps & Features, or use `msiexec /x pmg_Windows_x86_64.msi /qn` with the same MSI build you installed.

What the MSI does:

- Uninstall runs `pmg setup remove --system --config-file`, then deletes the binary. The managed config goes too, as with the MDM uninstall script.
- Uninstall deletes the shim directory even when pmg cannot run, so no shim outlives the binary.
- A cancelled or failed uninstall restores the shims, the PATH entry and the managed config.
- The PATH entry for the directory of `pmg.exe` stays after uninstall, as after `pmg setup remove --system`.
- An upgrade under a running `pmg.exe` renames the running file to `pmg.exe.old.<product code>` and installs the new file at once. The process keeps the old build until it restarts.
- `msiexec` can return 3010 (restart required) for such an upgrade. The new file is in place and no restart is needed. An MDM can map 3010 to success for this package.
- The next upgrade or the uninstall deletes old backups. A backup a process still holds stays until an administrator deletes it.
- For a running executable of the installed build, Windows Installer can defer deletion of the locked file until restart.
  A backup held by a process from before an upgrade remains with its directory until an administrator removes it after that process exits.
- An edge release ships an MSI too, listed as `pmg (edge)`. It replaces a stable install of the same version, and the next stable build replaces it.

`--system` checks the binary because every user's shim runs it by absolute path. On Linux, root must own the binary and its immediate directory.
No group or other account may write the binary.
The directory must have no other-write permission, but the current check accepts group-write.
Every user must be able to execute the binary and search each ancestor directory. On Windows, the binary must be at the path above, with no link or junction in that path. The install then sets one security descriptor on each object it owns: Administrators as owner, full control for SYSTEM and Administrators, read and execute for Users, no inheritance. `pmg setup doctor` reports an object whose descriptor differs. A reinstall restores descriptors on administrator-owned binaries, directories, and shims.
It refuses a managed config with a different descriptor or an object owned by another account.
Inspect and remove or redeploy that object deliberately before reinstalling.

For a Linux manual install, put the downloaded binary in a protected system directory before setup.
Do not assume `install.sh` chose `/usr/local/bin`.
It can select a user-local path based on `HOME` and `PATH`.
For example, after extracting a verified archive, run the following commands.

```sh
sudo install -o root -g root -m 0755 ./pmg /usr/local/bin/pmg
sudo /usr/local/bin/pmg setup install --system
```

Rerun elevated system setup after moving the binary or upgrading to a release that adds managers or changes paths.
It regenerates shims with the current absolute executable path and merges missing template keys.
An old shim can otherwise use an old binary or fail with exit 127.
Homebrew or another install method must meet the same actual ownership and access checks.

Per-user `pmg setup install` remains available and does not conflict with a system install.

To uninstall:

```bash
sudo pmg setup remove --system
sudo pmg setup remove --system --config-file   # also remove the system config file
```

On Windows, run the same two commands without `sudo`, from a terminal started as administrator.

Setup removal leaves the PMG binary and each user's runtime data.
Certificate trust has a separate [removal procedure](cert.md#trust-scopes).

## Files created


| Item                  | Linux                         | Windows                                 |
| --------------------- | ----------------------------- | --------------------------------------- |
| Configuration         | `/etc/safedep/pmg/config.yml` | `%PROGRAMDATA%\safedep\pmg\config.yml`  |
| Package-manager shims | `/usr/local/lib/pmg/bin`      | `%ProgramFiles%\safedep\pmg\bin\*.cmd`  |
| PATH                  | `/etc/profile.d/pmg.sh`       | Machine `PATH`: shim directory first, `pmg.exe` directory appended |


## Making shims visible on PATH

Processes only use the shims when the shim directory is on `PATH` ahead of the real `npm`, `pip`, and other package managers. On Linux that directory is `/usr/local/lib/pmg/bin`.

### Windows

`pmg setup install --system` puts `%ProgramFiles%\safedep\pmg\bin` first on the machine `PATH`. Windows builds the process `PATH` from the machine value, then the user value. The shims are therefore ahead of `npm` from the Node.js MSI and other machine-wide installers. The install also appends the directory of `pmg.exe`, so `pmg` resolves in every terminal. Open a new terminal after the install. `pmg setup remove --system` deletes the shim entry and keeps the `pmg.exe` entry.

A per-user install cannot do this. A user `PATH` entry never comes before a machine entry. A user-writable directory must not be on the machine `PATH`, because an elevated process could run a binary that a standard user put there.

Confirm with:

```powershell
Get-Command npm    # should resolve under %ProgramFiles%\safedep\pmg\bin
pmg setup doctor
```

### Linux VMs and login shells

`pmg setup install --system` installs `/etc/profile.d/pmg.sh`, which prepends the shim directory for login shells.

```bash
sudo pmg setup install --system
```

Only login shells that load this POSIX snippet pick it up automatically.
Bash, sh, and dash commonly load it through `/etc/profile`.
zsh on Debian or Ubuntu and fish do not normally load `/etc/profile.d`.
Arrange shim-first PATH in their system startup configuration.
Services, schedulers, sudo policies, and remote commands can also use a different PATH.
Set it explicitly or use the PMG prefix in each such context. For an already open shell, start a new login session or run:

```bash
source /etc/profile.d/pmg.sh
```

Confirm with:

```bash
which npm    # should resolve under /usr/local/lib/pmg/bin
pmg setup doctor
```


Experimental Go and Cargo get no system shim.
Use `pmg go` and `pmg cargo` explicitly.

### Docker and container images

Docker `RUN` does not load `/etc/profile.d`. After system install you **must** set `ENV PATH` so build steps and the runtime container see the shims:

```dockerfile
FROM node:22-bookworm

RUN curl -fsSL https://raw.githubusercontent.com/safedep/pmg/main/install.sh | sh \
 && pmg setup install --system

# Required: profile.d is not sourced during docker build
ENV PATH="/usr/local/lib/pmg/bin:$PATH"

# Optional: switch user; PATH from ENV still applies
RUN mkdir -p /app && chown node:node /app
WORKDIR /app
USER node
COPY --chown=node:node package*.json ./
RUN npm ci
```

Derived images inherit that `ENV`. Later `RUN npm install` / `RUN pip install` go through PMG for any `USER`.

If a child Dockerfile sets `ENV PATH=...` again, keep `/usr/local/lib/pmg/bin` ahead of the real `npm`/`pip` directories. Leaving it out (or behind those toolchains) drops interception.

Host shims and aliases do not see installs inside `docker build`.
Install PMG in the image as above, or use an enforcing host proxy with [namespace redirect](persistent-proxy.md#containers-and-other-network-namespaces).

## Configuration

An accepted system config governs every user and replaces each per-user file.
Linux uses `/etc/safedep/pmg/config.yml`.
Windows uses `%PROGRAMDATA%\safedep\pmg\config.yml`.
macOS has no system shim install but accepts `/Library/Application Support/safedep/pmg/config.yml`.
Deploy it through MDM or `sudo pmg config edit --system`.
Without `global_lockdown: true`, environment variables and CLI flags can override the managed values.
This includes `PMG_INSECURE_INSTALLATION`, which bypasses malware analysis.
Enable [lockdown](config.md#lockdown) to refuse managed configuration overrides.

Without `--system`, `pmg config set` and `pmg config edit` refuse to change a managed configuration.
Use `sudo pmg config set --system <key> <value>` or `sudo pmg config edit --system`.
On Windows, omit sudo and use an administrator terminal.
You can also redeploy the file through configuration management.

On Windows, the install sets the same security descriptor on `%PROGRAMDATA%\safedep`, `%PROGRAMDATA%\safedep\pmg` and the config file. A `config.yml` that already exists there is kept only when it carries that descriptor. Any other file stops the install with a message that names it. Inspect the file, delete it, and run the install again. For an MDM deployment, run `pmg setup install --system` first, then edit the file it writes.

At run time, current PMG obeys the managed file only when its trust check accepts the path.
The Unix full-path ownership check first appeared in `v0.34.0-edge.2`.
Older Unix builds, including v0.33.0 and v0.34.0-edge.1, do not provide this check.
Administrators of those versions must secure the entire path themselves.

- **Linux and macOS.** Root must own the file and each directory from `/` down to it. No group or other write is allowed. A sticky directory, such as `/tmp`, can be an exception.
  This exception does not cover the two directories directly above the config file. A directory on a read-only mount is also an exception, because no account can create or rename an entry through that mount. A file on a read-only mount gets no exception: the source of a read-only bind mount can stay writable, so the file must still have no group or other write. Keep the source folder of a bind mount owned by root with no group or other write. PMG cannot see that folder from inside the mount. If another account can write it, that account can remove or replace the file, and lockdown then turns off. A link is followed only when root owns it, and its target must pass the same check. A NixOS `environment.etc` link passes. A Kubernetes ConfigMap volume passes: its directory has the mode `0777`, but the kubelet mounts it read-only. A `subPath` mount also passes, but Kubernetes does not update it when the ConfigMap changes.
- **Windows.** Administrators or SYSTEM must own the file and the two directories above it, and no other account may write any of the three.

Otherwise PMG ignores the file, and the per-user config applies. `global_lockdown` then has no effect. Each `pmg` command prints a warning that names the path the check refused. `pmg setup info` shows the reason, and `pmg setup info --json` puts it in `config.managed_config_error`. The "Managed config" row of `pmg setup doctor` fails. On Windows, `pmg setup doctor` also reports a managed config whose descriptor differs from the one the install wrote.

`pmg setup install --system` checks the same rule after it writes the file. The install keeps a directory that already exists, such as an `/etc/safedep` that another account owns or that its group may write. In that case, the install fails and names the path. Fix the owner or the mode with `sudo chown root <path>` and `sudo chmod go-w <path>`, then run the install again.

Optional lockdown (`global_lockdown: true`) is documented in [config.md](./config.md).

For a Windows MDM fleet, the scripts in [`scripts/mdm`](../scripts/mdm) run the system install and deploy a managed config. The Linux scripts deploy a managed config and a per-user setup.

## Limitations

- **Virtualenv.** After `source .venv/bin/activate`, bare `pip` uses the venv binary and skips PMG shims. Call `pmg pip …` explicitly.
- **Version managers.** Tools like nvm, pyenv, volta, and asdf often prepend their own bin directories from shell rc files that run after `/etc/profile.d`. That can put real `npm`/`pip` ahead of PMG shims even when the shim directory is on `PATH`. Prefer putting `/usr/local/lib/pmg/bin` first in a durable `ENV PATH` / login PATH, or call `pmg npm` / `pmg pip` explicitly. `pmg setup doctor` warns for any supported package manager that resolves outside the shim directory.
- **No shell aliases.** System install only installs PATH shims. There is no `pmg.rc` alias layer.
- **Config changes.** Plain `pmg config set` and `pmg config edit` refuse while managed configuration is active.
  Use `--system` as root or an administrator, or redeploy the file.
- **Custom sandbox `policy_templates`.** A relative path in the system config resolves under `/etc/safedep/pmg`, next to the file that declares it.
- **`pmg sandbox allow`.** Blocked when the system config sets `global_lockdown: true`.
- **Group-writable install directory.** The binary must be root-owned and non-writable, but if its directory is group-writable without the sticky bit (for example, an upgraded pre-Debian-10 host retaining `root:staff` mode `2775`), a group member can delete the root-owned binary and replace it, bypassing the check. On a host where that group is not trusted, run `sudo chmod g-w /usr/local/bin` or install into a `root:root` directory.
- **Elevation only, not impersonation.** Root's per-user data is diverted to `/root` only for `sudo` to root (detected via `SUDO_USER`). Plain `su` has no `SUDO_USER` marker and normally resets HOME to root's home.
  It can retain `XDG_*` or `PMG_*` directory overrides from the caller.
  `su -m` or `su -p` can also retain HOME.
  These retained values can create root-owned state in the caller's directories. `sudo -u <user>` runs with only that user's rights, so it cannot poison another account at all, it just fails. Prefer `sudo` or `su -`, or set `PMG_CONFIG_DIR`.


## User data directories

Shared policy lives under `/etc/safedep/pmg`. Runtime data stays per user.
The table shows Linux defaults.
On Windows, config and `cloud-sync.db` use `%APPDATA%\safedep\pmg`.
Cache, local data, and `logs` use `%LOCALAPPDATA%\safedep\pmg`.
See [Windows paths](windows-support.md#files-created).


| Data                  | Default location                                  |
| --------------------- | ------------------------------------------------- |
| Event logs            | `~/.config/safedep/pmg/logs/`                     |
| Cloud sync state      | `~/.config/safedep/pmg/cloud-sync.db`             |
| Cache                 | `~/.cache/safedep/pmg/`                           |
| Sandbox overlays      | `~/.config/safedep/pmg/sandbox/overlays/`         |
| Persistent CA keypair | `~/.config/safedep/pmg/ca-cert.pem`, `ca-key.pem` |

You can relocate these with `PMG_CONFIG_DIR` and `PMG_CACHE_DIR`.

When pmg runs under `sudo` (a non-root user elevated to root), its per-user data resolves under root's own home (`/root`), not the invoking user's, even if sudo preserved their `HOME`. Running directly as root honors `HOME`/`XDG_CONFIG_HOME` as usual, so golden images that set those on purpose keep working. This detection relies on sudo's `SUDO_USER` marker: Plain `su` normally resets HOME but can retain XDG or PMG directory overrides.
`su -m` and `su -p` can preserve HOME too.
These values can send root's state into another user's directories. Prefer `su -` or `sudo`.

The invoking user must be able to write their config directory. PMG records an event log in the effective log directory on each run and fails the command if it cannot (unless event logging is disabled in config).

In Docker images, avoid creating `/home/<user>/.config/safedep` as root during the build. Either fix ownership for the runtime user, or set `PMG_CONFIG_DIR` to a writable location.

If every `pmg` command fails with `permission denied` on the event log, check where the reported path points:

- **Inside your own home**: a root run created it as root (a retained directory override, a preserved HOME, an image with the wrong HOME, or an older sudo build). Restore ownership: `sudo chown -R $(id -un) ~/.config/safedep`
- **Inside another user's home**: your environment leaked that user's `HOME` or `XDG_CONFIG_HOME` (e.g. `sudo -u <user>` on GitHub-hosted runners). If only `XDG_CONFIG_HOME` leaked, set `export XDG_CONFIG_HOME="$HOME/.config"`.
  If HOME is wrong, run with the target user's own HOME, for example through `sudo -H -u <user>`. Do not chown another user's directory; that bricks their pmg instead.

The error message and `pmg setup doctor` print the fix matching your case.

For cloud sync, enable cloud in the system config and provide credentials (`SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID`, or a keychain login on developer machines).

For MDM fleets, schedule `pmg cloud sync` for each user who generates events.
Use that user's credentials and config directory through a launchd agent, systemd user timer, or per-user MDM script.
A root timer does not drain other users' queues.
Automatic sync can also deliver events when enabled. Each sync also sends a rate-limited check-in, so an idle endpoint still appears as active in the SafeDep Cloud Endpoints view.

## Certificates

System install does not set up a MITM certificate authority. For npm and pip on Linux, PMG's default ephemeral CA and environment-variable injection are enough.

To install a persistent CA into the OS trust store, use a separate command:

```bash
pmg setup cert install --system
```

On Linux, run it as your normal user for a user-owned keypair with system-wide public trust.
PMG elevates only the trust-store write.
A Linux root run writes the keypair to `/etc/safedep/pmg` for the enforcing daemon.
Per-user PMG runs do not use that root keypair.
On Windows, use an elevated prompt for system trust.
See [cert.md](cert.md) for account and scope details.
