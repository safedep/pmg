#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
GENERATOR="${SCRIPT_DIR}/generate_standalone_scripts.sh"
INSTALLER="${SCRIPT_DIR}/standalone/pmg_setup_install_macos_standalone.sh"
UNINSTALLER="${SCRIPT_DIR}/standalone/pmg_uninstall_macos_standalone.sh"
TEST_ROOT=$(mktemp -d)
CONFIG="${TEST_ROOT}/config.yml"
CONFIGURED_OUTPUT="${TEST_ROOT}/configured"
GLOBAL_CONFIG="/Library/Application Support/safedep/pmg/config.yml"
USER_CONFIG="${HOME}/Library/Application Support/safedep/pmg/config.yml"
OPT_BREW_DISABLED=0
USR_BREW_DISABLED=0

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

log() {
  echo "==> $*"
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_absent() {
  [[ ! -e "$1" && ! -L "$1" ]] || fail "path still exists: $1"
}

assert_equals() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  [[ "$actual" == "$expected" ]] ||
    fail "$message: expected '$expected', got '$actual'"
}

installed_pmg() {
  local candidate
  for candidate in /usr/local/bin/pmg /opt/homebrew/bin/pmg; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

assert_uninstalled() {
  assert_absent /usr/local/bin/pmg
  assert_absent /opt/homebrew/bin/pmg
  assert_absent "$GLOBAL_CONFIG"
  assert_absent "$USER_CONFIG"
}

disable_brew() {
  local disabled=0
  if [[ -e /opt/homebrew/bin/brew || -L /opt/homebrew/bin/brew ]]; then
    sudo -n mv /opt/homebrew/bin/brew /opt/homebrew/bin/brew.pmg-macos-e2e-disabled
    OPT_BREW_DISABLED=1
    disabled=1
  fi
  if [[ -e /usr/local/bin/brew || -L /usr/local/bin/brew ]]; then
    sudo -n mv /usr/local/bin/brew /usr/local/bin/brew.pmg-macos-e2e-disabled
    USR_BREW_DISABLED=1
    disabled=1
  fi
  [[ "$disabled" -eq 1 ]] || fail "Homebrew is required to verify the release fallback"
}

restore_brew() {
  if [[ "$OPT_BREW_DISABLED" -eq 1 ]]; then
    sudo -n mv /opt/homebrew/bin/brew.pmg-macos-e2e-disabled /opt/homebrew/bin/brew
    OPT_BREW_DISABLED=0
  fi
  if [[ "$USR_BREW_DISABLED" -eq 1 ]]; then
    sudo -n mv /usr/local/bin/brew.pmg-macos-e2e-disabled /usr/local/bin/brew
    USR_BREW_DISABLED=0
  fi
}

cleanup() {
  set +e
  restore_brew
  sudo -n "$UNINSTALLER" >/dev/null 2>&1
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

test_standalone_release_install() {
  local pmg_bin

  log "Testing standalone release fallback without Homebrew"
  disable_brew
  sudo -n "$INSTALLER"
  pmg_bin=$(installed_pmg) || fail "release fallback did not install pmg"
  assert_equals "/usr/local/bin/pmg" "$pmg_bin" "release fallback install path"
  "$pmg_bin" version >/dev/null
  assert_absent "$GLOBAL_CONFIG"
  assert_file "$USER_CONFIG"

  sudo -n "$UNINSTALLER"
  assert_uninstalled
  restore_brew
}

test_configured_install() {
  local pmg_bin

  log "Testing embedded global config"
  cat > "$CONFIG" <<'EOF'
paranoid: true
EOF
  "$GENERATOR" --config "$CONFIG" --output-dir "$CONFIGURED_OUTPUT"

  local configured_installer="${CONFIGURED_OUTPUT}/pmg_setup_install_macos_standalone.sh"
  local configured_uninstaller="${CONFIGURED_OUTPUT}/pmg_uninstall_macos_standalone.sh"

  sudo -n "$configured_installer"
  pmg_bin=$(installed_pmg) || fail "configured installer did not install pmg"
  "$pmg_bin" version >/dev/null
  assert_file "$GLOBAL_CONFIG"
  cmp "$CONFIG" "$GLOBAL_CONFIG"
  assert_equals "root" "$(stat -f '%Su' "$GLOBAL_CONFIG")" \
    "global config owner"
  assert_equals "644" "$(stat -f '%Lp' "$GLOBAL_CONFIG")" \
    "global config mode"
  assert_absent "$USER_CONFIG"
  assert_equals "true" "$("$pmg_bin" config get paranoid)" \
    "global config value"

  sudo -n "$configured_uninstaller"
  assert_uninstalled
}

sudo -n true || fail "passwordless sudo is required"
sudo -n "$UNINSTALLER"
assert_uninstalled

test_standalone_release_install
test_configured_install
echo "PASS"
