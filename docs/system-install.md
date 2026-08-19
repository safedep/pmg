# System Install (Linux)

Use system install when one machine or image should protect every user account: shared VMs, golden Docker images, and similar setups.

```bash
sudo pmg setup install --system
```

**Requires Linux and root.** Install PMG as root into a standard system path such as `/usr/local/bin`. A user-local build (e.g. `~/go/bin/pmg`) is rejected.

`--system` enforces this because every user's shims run the PMG binary by absolute path. Before installing, it checks that the binary is **root-owned**, world-executable, not group- or other-writable, located in a **root-owned directory** that isn't world-writable, and reachable through world-searchable directories (a binary under `/root`, mode 0700, is rejected because other users could never execute it).

Per-user `pmg setup install` remains available and does not conflict with a system install.

To uninstall:

```bash
sudo pmg setup remove --system
sudo pmg setup remove --system --config-file   # also remove the system config file
```

## Files created


| Item                  | Path                          |
| --------------------- | ----------------------------- |
| Configuration         | `/etc/safedep/pmg/config.yml` |
| Package-manager shims | `/usr/local/lib/pmg/bin`      |
| Shell PATH snippet    | `/etc/profile.d/pmg.sh`       |


## Making shims visible on PATH

System install writes shims to `/usr/local/lib/pmg/bin`. Processes only use them when that directory is on `PATH` ahead of the real `npm`, `pip`, and other package managers.

### Linux VMs and login shells

`pmg setup install --system` installs `/etc/profile.d/pmg.sh`, which prepends the shim directory for login shells.

```bash
sudo pmg setup install --system
```

New login sessions pick this up automatically. For an already open shell, start a new login session or run:

```bash
source /etc/profile.d/pmg.sh
```

Confirm with:

```bash
which npm    # should resolve under /usr/local/lib/pmg/bin
pmg setup doctor
```


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

PMG running on the Docker host cannot inspect package installations inside `docker build`. PMG must be installed in the image as shown above.

## Configuration

The system config file is authoritative for every user. A per-user `config.yml` is ignored while `/etc/safedep/pmg/config.yml` exists.

`pmg config set` and `pmg config edit` fail under a system config. Update the file as root, or redeploy it through your image or configuration management.

Optional lockdown (`global_lockdown: true`) is documented in [config.md](./config.md).

## Limitations

- **Virtualenv.** After `source .venv/bin/activate`, bare `pip` uses the venv binary and skips PMG shims. Call `pmg pip …` explicitly.
- **Version managers.** Tools like nvm, pyenv, volta, and asdf often prepend their own bin directories from shell rc files that run after `/etc/profile.d`. That can put real `npm`/`pip` ahead of PMG shims even when the shim directory is on `PATH`. Prefer putting `/usr/local/lib/pmg/bin` first in a durable `ENV PATH` / login PATH, or call `pmg npm` / `pmg pip` explicitly. `pmg setup doctor` warns for any supported package manager that resolves outside the shim directory.
- **No shell aliases.** System install only installs PATH shims. There is no `pmg.rc` alias layer.
- **Config changes.** `pmg config set` and `pmg config edit` are unavailable while the system config is active. Edit `/etc/safedep/pmg/config.yml` as root, or redeploy the file.
- **Custom sandbox `policy_templates`.** Relative paths in the system config resolve under each user's config directory, not `/etc/safedep/pmg`. Prefer absolute paths.
- **`pmg sandbox allow`.** Blocked when the system config sets `global_lockdown: true`.
- **Group-writable install directory.** The binary must be root-owned and non-writable, but if its directory is group-writable without the sticky bit (Debian/Ubuntu ship `/usr/local/bin` as `root:staff` mode `2775`), a group member can delete the root-owned binary and replace it, bypassing the check. `staff` is empty by default, so default exposure is nil; on a multi-user host where the group is not trusted, run `sudo chmod g-w /usr/local/bin` or install into a `root:root` directory.
- **Elevation only, not impersonation.** Root's per-user data is diverted to `/root` only for `sudo` to root (detected via `SUDO_USER`). `su` without `-` becomes root with no marker, so it can still create root-owned files in the caller's home; the caller sees a clear error and chown fix on their next `pmg` run. `sudo -u <user>` runs with only that user's rights, so it cannot poison another account at all, it just fails. Prefer `sudo` or `su -`, or set `PMG_CONFIG_DIR`.


## User data directories

Shared policy lives under `/etc/safedep/pmg`. Runtime data stays per user:


| Data                  | Default location                                  |
| --------------------- | ------------------------------------------------- |
| Event logs            | `~/.config/safedep/pmg/logs/`                     |
| Cloud sync state      | `~/.config/safedep/pmg/cloud-sync.db`             |
| Cache                 | `~/.cache/safedep/pmg/`                           |
| Sandbox overlays      | `~/.config/safedep/pmg/sandbox/overlays/`         |
| Persistent CA keypair | `~/.config/safedep/pmg/ca-cert.pem`, `ca-key.pem` |

You can relocate these with `PMG_CONFIG_DIR` and `PMG_CACHE_DIR`.

When pmg runs under `sudo` (a non-root user elevated to root), its per-user data resolves under root's own home (`/root`), not the invoking user's, even if sudo preserved their `HOME`. Running directly as root honors `HOME`/`XDG_CONFIG_HOME` as usual, so golden images that set those on purpose keep working. This detection relies on sudo's `SUDO_USER` marker: `su` without `-` leaks the caller's environment but leaves no marker, so a root shell obtained that way can still write into the caller's home. Prefer `su -` or `sudo`.

The invoking user must be able to write their config directory. PMG records an event log there on each run and fails the command if it cannot (unless event logging is disabled in config).

In Docker images, avoid creating `/home/<user>/.config/safedep` as root during the build. Either fix ownership for the runtime user, or set `PMG_CONFIG_DIR` to a writable location.

If every `pmg` command fails with `permission denied` on the event log, check where the reported path points:

- **Inside your own home**: a root run created it as root (`su` without `-`, images that set `ENV HOME` before dropping root, or an older pmg under `sudo`). Restore ownership: `sudo chown -R $(id -un) ~/.config/safedep`
- **Inside another user's home**: your environment leaked that user's `HOME` or `XDG_CONFIG_HOME` (e.g. `sudo -u <user>` on GitHub-hosted runners). Fix the environment (`export XDG_CONFIG_HOME="$HOME/.config"`). Do not chown another user's directory; that bricks their pmg instead.

The error message and `pmg setup doctor` print the fix matching your case.

For cloud sync, enable cloud in the system config and provide credentials (`SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID`, or a keychain login on developer machines).

## Certificates

System install does not set up a MITM certificate authority. For npm and pip on Linux, PMG's default ephemeral CA and environment-variable injection are enough.

To install a persistent CA into the OS trust store, use a separate command:

```bash
pmg setup cert install --system
```

Run that as your normal user. Details are in [cert.md](./cert.md).
