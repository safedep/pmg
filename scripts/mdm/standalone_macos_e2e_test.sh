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

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_absent() {
  [[ ! -e "$1" && ! -L "$1" ]] || fail "path still exists: $1"
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

cleanup() {
  set +e
  sudo -n "$UNINSTALLER" >/dev/null 2>&1
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

sudo -n true || fail "passwordless sudo is required"
sudo -n "$UNINSTALLER"
assert_uninstalled

sudo -n "$INSTALLER"
PMG_BIN=$(installed_pmg) || fail "pmg was not installed"
"$PMG_BIN" version >/dev/null
assert_absent "$GLOBAL_CONFIG"
assert_file "$USER_CONFIG"

sudo -n "$UNINSTALLER"
assert_uninstalled

cat > "$CONFIG" <<'EOF'
global_lockdown: true
EOF
"$GENERATOR" --config "$CONFIG" --output-dir "$CONFIGURED_OUTPUT"

CONFIGURED_INSTALLER="${CONFIGURED_OUTPUT}/pmg_setup_install_macos_standalone.sh"
CONFIGURED_UNINSTALLER="${CONFIGURED_OUTPUT}/pmg_uninstall_macos_standalone.sh"

sudo -n "$CONFIGURED_INSTALLER"
PMG_BIN=$(installed_pmg) || fail "pmg was not installed by configured installer"
"$PMG_BIN" version >/dev/null
assert_file "$GLOBAL_CONFIG"
cmp "$CONFIG" "$GLOBAL_CONFIG"
[[ "$(stat -f '%Su' "$GLOBAL_CONFIG")" == "root" ]] ||
  fail "global config is not owned by root"
[[ "$(stat -f '%Lp' "$GLOBAL_CONFIG")" == "644" ]] ||
  fail "global config does not have mode 0644"
assert_absent "$USER_CONFIG"

sudo -n "$CONFIGURED_UNINSTALLER"
assert_uninstalled

echo "PASS"
