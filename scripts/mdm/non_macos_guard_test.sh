#!/bin/bash
# non_macos_guard_test.sh — verify that every MDM entry script refuses to run
# on a non-macOS host before it makes any change. Run on a Linux CI runner.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "SKIP: this test runs on a non-macOS host"
  exit 0
fi

SCRIPTS=(
  pmg_setup_install_macos.sh
  pmg_uninstall_macos.sh
  standalone/pmg_setup_install_macos_standalone.sh
  standalone/pmg_uninstall_macos_standalone.sh
)

for script in "${SCRIPTS[@]}"; do
  if output=$(bash "${SCRIPT_DIR}/${script}" 2>&1); then
    fail "$script must refuse to run on $(uname -s)"
  fi
  [[ "$output" == *"this script is for macOS only"* ]] ||
    fail "$script did not print the macOS-only error: $output"
done

echo "PASS"
