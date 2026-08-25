#!/bin/bash
# os_guard_test.sh — verify that every MDM entry script refuses to run on the
# wrong OS before it makes any change. Runs the macOS half on Linux and the
# Linux half on macOS; skips whichever half matches the host.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

host="$(uname -s)"

check_guard() {
  local os="$1"
  local wrong_host_msg="$2"
  shift 2

  for script in "$@"; do
    if output=$(bash "${SCRIPT_DIR}/${script}" 2>&1); then
      fail "$script must refuse to run on $host"
    fi
    [[ "$output" == *"$wrong_host_msg"* ]] ||
      fail "$script did not print the $os-only error: $output"
  done
}

if [[ "$host" != "Darwin" ]]; then
  check_guard "macOS" "this script is for macOS only" \
    macos/pmg_setup_install_macos.sh \
    macos/pmg_uninstall_macos.sh \
    standalone/pmg_setup_install_macos_standalone.sh \
    standalone/pmg_uninstall_macos_standalone.sh
else
  echo "SKIP: macOS guard half requires a non-macOS host"
fi

if [[ "$host" != "Linux" ]]; then
  check_guard "Linux" "this script is for Linux only" \
    linux/pmg_setup_install_linux.sh \
    linux/pmg_uninstall_linux.sh \
    standalone/pmg_setup_install_linux_standalone.sh \
    standalone/pmg_uninstall_linux_standalone.sh
else
  echo "SKIP: Linux guard half requires a non-Linux host"
fi

echo "PASS"
