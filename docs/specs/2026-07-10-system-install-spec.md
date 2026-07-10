# System Install (`pmg setup install --system`) Spec

Date: 2026-07-10  
Issue: [#317](https://github.com/safedep/pmg/issues/317)  
Prerequisite: [#323](https://github.com/safedep/pmg/pull/323) (`PMG_SHIM_PATH`)

## Problem

`pmg setup install` writes shims and shell integration relative to the invoking user's HOME. When root installs PMG in a golden Docker image (or shared VM) and a later `USER` / non-root account runs package managers, those users do not get interception.

Host-side PMG (e.g. GitHub Actions) also cannot see package installs that happen inside `docker build`.

## Goal

Root can install PMG once for all users on a Linux host. Feature is a **general Linux system install**, motivated by Docker golden images but not Docker-specific.

## Non-goals (v1)

- macOS / Windows `--system`
- Persistent proxy baked into images
- In-place wrap of binaries under `/usr/local/bin`
- Shell function wrappers for venv PATH races
- Host PMG intercepting `docker build` from outside the image

## Behaviour

### Artifacts

| Artifact | Path |
|----------|------|
| Config | `/etc/safedep/pmg/config.yml` |
| Shims | `/usr/local/lib/pmg/bin/<pm>` |
| Login PATH | `/etc/profile.d/pmg.sh` (prepends shim dir) |

Per-user cache and event logs stay per-user.

### CLI

```bash
sudo pmg setup install --system
sudo pmg setup remove --system
sudo pmg setup remove --system --config-file   # also remove system config
```

- Non-root `--system` → fail with `PermissionDenied` and sudo guidance
- Non-Linux `--system` → fail with `UnsupportedPlatform`
- Root without `--system` → warn, then per-user install into root's HOME
- System and per-user layers are independent

### PATH

- **VMs / login shells:** `/etc/profile.d/pmg.sh` prepends the shim dir
- **Docker `RUN`:** image must set `ENV PATH="/usr/local/lib/pmg/bin:$PATH"` (profile.d is not sourced)

### Limitations

- After `venv/bin/activate`, `pip` resolves to the venv binary and bypasses shims. Use `pmg pip …`.
- Child Dockerfiles that rewrite `PATH` without the shim dir lose interception.

### Event logging

If event log initialization fails (e.g. unusable HOME), PMG warns and continues instead of exiting.

## Testing

- Unit tests with overridden system paths
- Install/remove idempotence for system shims and profile.d
- Doctor/info report system scope
