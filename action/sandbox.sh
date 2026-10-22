#!/bin/sh
# Prepares the runner for the PMG sandbox. Reads INPUT_DRIVER and
# PMG_JOB_CONTAINER.
set -eu
# The sandbox uses kernel features of the runner host. In a job
# container the AppArmor change below cannot reach the host.
if [ "$PMG_JOB_CONTAINER" = true ]; then
  printf '%s\n' "::warning::The sandbox runs in a job container. The action cannot relax AppArmor on the runner host from here, so the sandbox may not start."
fi
if [ "$INPUT_DRIVER" = "bubblewrap" ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' "::error::sandbox-driver bubblewrap installs bubblewrap with apt-get, and this image has no apt-get. Use an Ubuntu runner or image." >&2
    exit 1
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y bubblewrap
  else
    apt-get update
    apt-get install -y bubblewrap
  fi
fi

# Relax AppArmor restriction on unprivileged user namespaces so
# Landlock helper and Bubblewrap can clone with CLONE_NEWUSER.
# Tolerate failure on locked-down runners; the sandbox driver will
# report a clear error at runtime if it cannot start.
if command -v sudo >/dev/null 2>&1; then
  sudo systemctl stop apparmor 2>/dev/null || true
  sudo systemctl disable apparmor 2>/dev/null || true
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
else
  systemctl stop apparmor 2>/dev/null || true
  systemctl disable apparmor 2>/dev/null || true
  sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
fi
