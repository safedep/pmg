#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd -P)
GENERATOR="${SCRIPT_DIR}/generate_standalone_scripts.sh"
INSTALLER="${SCRIPT_DIR}/standalone/pmg_setup_install_macos_standalone.sh"
UNINSTALLER="${SCRIPT_DIR}/standalone/pmg_uninstall_macos_standalone.sh"
INSTALL_SH="${REPO_ROOT}/install.sh"
TEST_ROOT=$(mktemp -d)
CONFIG="${TEST_ROOT}/config.yml"
CONFIGURED_OUTPUT="${TEST_ROOT}/configured"
GLOBAL_CONFIG="/Library/Application Support/safedep/pmg/config.yml"
USER_CONFIG="${HOME}/Library/Application Support/safedep/pmg/config.yml"
ADVISORY_MESSAGE="PMG macOS E2E policy"
TEST_API_KEY="pmg-macos-e2e-api-key"
TEST_TENANT_ID="pmg-macos-e2e.invalid"
OPT_BREW_DISABLED=0
USR_BREW_DISABLED=0
DEFAULT_SANDBOX=""
DEFAULT_RETENTION=""

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

keychain_value() {
  security find-generic-password -s safedep -a "$1" -w
}

assert_keychain_absent() {
  if security find-generic-password -s safedep -a "$1" -w >/dev/null 2>&1; then
    fail "keychain entry still exists: $1"
  fi
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

test_install_sh() {
  local install_home="${TEST_ROOT}/install-sh-home"
  local install_bin="${install_home}/.local/bin/pmg"

  log "Testing install.sh release installation"
  mkdir -p "${install_home}/.local/bin"
  HOME="$install_home" PATH="${install_home}/.local/bin:${PATH}" sh "$INSTALL_SH"
  [[ -x "$install_bin" ]] || fail "install.sh did not install an executable"
  "$install_bin" version >/dev/null
  rm -f "$install_bin"
  assert_absent "$install_bin"
}

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

test_homebrew_install_with_keychain() {
  local pmg_bin

  log "Testing Homebrew installation and Keychain credentials"
  sudo -n env \
    SAFEDEP_API_KEY="$TEST_API_KEY" \
    SAFEDEP_TENANT_ID="$TEST_TENANT_ID" \
    "$INSTALLER"
  pmg_bin=$(installed_pmg) || fail "Homebrew installer did not install pmg"
  "$pmg_bin" version >/dev/null
  assert_absent "$GLOBAL_CONFIG"
  assert_file "$USER_CONFIG"

  assert_equals "$TEST_API_KEY" "$(keychain_value default/api_key)" \
    "stored API key"
  assert_equals "$TEST_TENANT_ID" "$(keychain_value default/tenant_domain)" \
    "stored tenant ID"

  DEFAULT_SANDBOX=$("$pmg_bin" config get sandbox.enabled)
  DEFAULT_RETENTION=$("$pmg_bin" config get event_log_retention_days)

  sudo -n "$UNINSTALLER"
  assert_uninstalled
  assert_keychain_absent default/api_key
  assert_keychain_absent default/tenant_domain
}

test_configured_install_and_policy() {
  local pmg_bin
  local block_output
  local package_dir="${TEST_ROOT}/package-test"

  log "Testing embedded managed config and package blocking"
  cat > "$CONFIG" <<EOF
global_lockdown: true
paranoid: true
advisory_message: "${ADVISORY_MESSAGE}"
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
    "managed paranoid value"
  assert_equals "\"${ADVISORY_MESSAGE}\"" \
    "$("$pmg_bin" config get advisory_message)" \
    "managed advisory message"
  assert_equals "$DEFAULT_SANDBOX" \
    "$("$pmg_bin" config get sandbox.enabled)" \
    "unspecified sandbox default"
  assert_equals "$DEFAULT_RETENTION" \
    "$("$pmg_bin" config get event_log_retention_days)" \
    "unspecified retention default"

  assert_equals "true" \
    "$(PMG_PARANOID=false "$pmg_bin" config get paranoid)" \
    "lockdown environment override"
  if "$pmg_bin" --paranoid=false config get paranoid >/dev/null 2>&1; then
    fail "lockdown allowed a managed CLI flag override"
  fi
  if "$pmg_bin" config set paranoid false >/dev/null 2>&1; then
    fail "managed config allowed config set"
  fi

  command -v npm >/dev/null 2>&1 || fail "npm is required for package blocking test"
  mkdir -p "$package_dir"
  if block_output=$(
    cd "$package_dir"
    "$pmg_bin" npm install --no-cache --prefer-online safedep-test-pkg@0.1.3 2>&1
  ); then
    fail "known malicious test package was not blocked"
  fi
  [[ "$block_output" == *"$ADVISORY_MESSAGE"* ]] ||
    fail "block output did not contain the managed advisory message"
  assert_absent "${package_dir}/node_modules/safedep-test-pkg"

  sudo -n "$configured_uninstaller"
  assert_uninstalled
}

sudo -n true || fail "passwordless sudo is required"
sudo -n "$UNINSTALLER"
assert_uninstalled

test_install_sh
test_standalone_release_install
test_homebrew_install_with_keychain
test_configured_install_and_policy
echo "PASS"
