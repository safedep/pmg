#!/bin/bash
set -euo pipefail

if [[ "${CI:-}" != "true" || "${PMG_MDM_E2E:-}" != "1" ]]; then
  echo "Error: standalone macOS E2E requires CI=true and PMG_MDM_E2E=1" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
GENERATOR="${SCRIPT_DIR}/generate_standalone_macos.sh"
INSTALLER="${SCRIPT_DIR}/standalone/pmg_setup_install_macos_standalone.sh"
UNINSTALLER="${SCRIPT_DIR}/standalone/pmg_uninstall_macos_standalone.sh"
# Keep the wrapper dir traversable by every local user. See e2e_lib_macos.sh.
TEST_ROOT=$(mktemp -d /tmp/pmg-mdm-e2e.XXXXXX)
chmod 0755 "$TEST_ROOT"
# shellcheck source=e2e_lib_macos.sh
source "${BASH_SOURCE[0]%/*}/e2e_lib_macos.sh"

CONFIG="${TEST_ROOT}/config.yml"
CONFIGURED_OUTPUT="${TEST_ROOT}/configured"
CREDENTIAL_OUTPUT="${TEST_ROOT}/credentials"
OPT_BREW_DISABLED=0
USR_BREW_DISABLED=0

create_pmg_wrapper

run_installer() {
  sudo -n /usr/bin/env PATH="$WRAPPER_PATH" "$@"
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
  run_uninstaller "$UNINSTALLER" >/dev/null 2>&1
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

test_standalone_release_install() {
  local pmg_bin

  log "Testing standalone release fallback without Homebrew"
  reset_wrapper_captures
  disable_brew
  run_installer "$INSTALLER"
  pmg_bin=$(installed_pmg) || fail "release fallback did not install pmg"
  assert_equals "/usr/local/bin/pmg" "$pmg_bin" "release fallback install path"
  "$pmg_bin" version >/dev/null
  assert_absent "$GLOBAL_CONFIG"
  assert_file "$USER_CONFIG"
  assert_no_login_recorded
  assert_no_sync_recorded
  assert_no_unexpected_cloud

  run_uninstaller "$UNINSTALLER"
  assert_no_unexpected_cloud
  assert_uninstalled
  restore_brew
}

test_configured_install() {
  local pmg_bin

  log "Testing embedded global config"
  reset_wrapper_captures
  cat > "$CONFIG" <<'EOF'
paranoid: true
EOF
  "$GENERATOR" --config "$CONFIG" --output-dir "$CONFIGURED_OUTPUT"
  cat > "${CONFIGURED_OUTPUT}/config.yml" <<'EOF'
paranoid: false
EOF

  local configured_installer="${CONFIGURED_OUTPUT}/pmg_setup_install_macos_standalone.sh"
  local configured_uninstaller="${CONFIGURED_OUTPUT}/pmg_uninstall_macos_standalone.sh"

  run_installer "$configured_installer"
  pmg_bin=$(installed_pmg) || fail "configured installer did not install pmg"
  "$pmg_bin" version >/dev/null
  assert_global_config_installed "$CONFIG"
  assert_absent "$USER_CONFIG"
  assert_equals "true" "$("$pmg_bin" config get paranoid)" \
    "global config value"
  assert_no_login_recorded
  assert_no_sync_recorded
  assert_no_unexpected_cloud

  run_uninstaller "$configured_uninstaller"
  assert_no_unexpected_cloud
  assert_uninstalled
}

test_cloud_credentials_install() {
  local pmg_bin

  log "Testing embedded cloud credentials"
  reset_wrapper_captures
  SAFEDEP_API_KEY="$TEST_API_KEY" \
    SAFEDEP_TENANT_ID="$TEST_TENANT_ID" \
    "$GENERATOR" \
    --embed-cloud-credentials \
    --output-dir "$CREDENTIAL_OUTPUT"

  local credential_installer="${CREDENTIAL_OUTPUT}/pmg_setup_install_macos_standalone.sh"
  local credential_uninstaller="${CREDENTIAL_OUTPUT}/pmg_uninstall_macos_standalone.sh"

  run_installer "$credential_installer"
  pmg_bin=$(installed_pmg) || fail "credential installer did not install pmg"
  assert_login_recorded
  assert_sync_recorded_for "$EXPECTED_IDENTITY"
  assert_no_unexpected_cloud
  assert_equals "true" "$("$pmg_bin" config get cloud.enabled)" \
    "cloud configuration"

  reset_wrapper_captures
  run_installer "$credential_installer" --cloud-sync-only
  assert_no_login_recorded
  assert_sync_recorded_for "$EXPECTED_IDENTITY"
  assert_no_unexpected_cloud

  run_uninstaller "$credential_uninstaller"
  assert_logout_recorded
  assert_no_unexpected_cloud
  assert_uninstalled
}

require_e2e_preconditions
run_uninstaller "$UNINSTALLER"
assert_no_unexpected_cloud
assert_uninstalled

test_standalone_release_install
test_configured_install
test_cloud_credentials_install
echo "PASS"
