#!/bin/bash
# Run the standalone Linux MDM scripts end to end on a disposable Linux CI
# runner. The test uses dummy cloud credentials. A pmg wrapper on PATH records
# cloud login and logout instead of reaching SafeDep Cloud.
set -euo pipefail

if [[ "${CI:-}" != "true" || "${PMG_MDM_E2E:-}" != "1" ]]; then
  echo "Error: standalone Linux E2E requires CI=true and PMG_MDM_E2E=1" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
GENERATOR="${SCRIPT_DIR}/generate_standalone_linux.sh"
INSTALLER="${SCRIPT_DIR}/standalone/pmg_setup_install_linux_standalone.sh"
UNINSTALLER="${SCRIPT_DIR}/standalone/pmg_uninstall_linux_standalone.sh"
# Keep the wrapper dir traversable by every local user. See e2e_lib_linux.sh.
TEST_ROOT=$(mktemp -d /tmp/pmg-mdm-e2e.XXXXXX)
chmod 0755 "$TEST_ROOT"
# shellcheck source=e2e_lib_linux.sh
source "${BASH_SOURCE[0]%/*}/e2e_lib_linux.sh"

CONFIG="${TEST_ROOT}/config.yml"
CONFIGURED_OUTPUT="${TEST_ROOT}/configured"
CREDENTIAL_OUTPUT="${TEST_ROOT}/credentials"

create_pmg_wrapper

run_installer() {
  sudo -n /usr/bin/env PATH="$WRAPPER_PATH" "$@"
}

cleanup() {
  set +e
  run_uninstaller "$UNINSTALLER" >/dev/null 2>&1
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

test_standalone_release_install() {
  local pmg_bin

  log "Testing standalone release install"
  reset_wrapper_captures
  run_installer "$INSTALLER"
  pmg_bin=$(installed_pmg) || fail "standalone installer did not install pmg"
  assert_equals "/usr/local/bin/pmg" "$pmg_bin" "standalone install path"
  "$pmg_bin" version >/dev/null
  assert_absent "$GLOBAL_CONFIG"
  assert_file "$USER_CONFIG"
  assert_no_login_recorded
  assert_no_unexpected_cloud

  run_uninstaller "$UNINSTALLER"
  assert_no_unexpected_cloud
  assert_uninstalled
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

  local configured_installer="${CONFIGURED_OUTPUT}/pmg_setup_install_linux_standalone.sh"
  local configured_uninstaller="${CONFIGURED_OUTPUT}/pmg_uninstall_linux_standalone.sh"

  run_installer "$configured_installer"
  pmg_bin=$(installed_pmg) || fail "configured installer did not install pmg"
  "$pmg_bin" version >/dev/null
  assert_global_config_installed "$CONFIG"
  assert_absent "$USER_CONFIG"
  assert_equals "true" "$("$pmg_bin" config get paranoid)" \
    "global config value"
  assert_no_login_recorded
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

  local credential_installer="${CREDENTIAL_OUTPUT}/pmg_setup_install_linux_standalone.sh"
  local credential_uninstaller="${CREDENTIAL_OUTPUT}/pmg_uninstall_linux_standalone.sh"

  run_installer "$credential_installer"
  pmg_bin=$(installed_pmg) || fail "credential installer did not install pmg"
  assert_login_recorded
  assert_no_unexpected_cloud
  assert_equals "true" "$("$pmg_bin" config get cloud.enabled)" \
    "cloud configuration"

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
