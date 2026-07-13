# System Install (Linux)

Use system install when one machine or image should protect every user account: shared VMs, golden Docker images, and similar setups.

```bash
sudo pmg setup install --system
```

Requires Linux and root. To uninstall:

```bash
sudo pmg setup remove --system
sudo pmg setup remove --system --config-file   # also remove the system config file
```

Per-user `pmg setup install` remains available and does not conflict with a system install.
The PMG executable used during setup must be executable by every user. Install PMG under a system path such as `/usr/local/bin`.

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
- **No shell aliases.** System install only installs PATH shims. There is no `~/.pmg.rc` alias layer.
- **Config changes.** `pmg config set` and `pmg config edit` are unavailable while the system config is active. Edit `/etc/safedep/pmg/config.yml` as root, or redeploy the file.
- **Custom sandbox `policy_templates`.** Relative paths in the system config resolve under each user's config directory, not `/etc/safedep/pmg`. Prefer absolute paths.
- **`pmg sandbox allow`.** Blocked when the system config sets `global_lockdown: true`.


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

The invoking user must be able to write their config directory.

In Docker images, avoid creating `/home/<user>/.config/safedep` as root during the build. Either fix ownership for the runtime user, or set `PMG_CONFIG_DIR` to a writable location.

For cloud sync, enable cloud in the system config and provide credentials (`SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID`, or a keychain login on developer machines).

## Certificates

System install does not set up a MITM certificate authority. For npm and pip on Linux, PMG's default ephemeral CA and environment-variable injection are enough.

To install a persistent CA into the OS trust store, use a separate command:

```bash
pmg setup cert install --system
```

Run that as your normal user. Details are in [cert.md](./cert.md).
