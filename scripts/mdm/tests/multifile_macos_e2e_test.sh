#!/bin/bash
# Run the multi-file MDM scripts end to end on a disposable macOS CI runner.
# The test uses dummy cloud credentials. A pmg wrapper on PATH records cloud
# login and logout instead of reaching SafeDep Cloud.
set -euo pipefail

if [[ "${CI:-}" != "true" || "${PMG_MDM_E2E:-}" != "1" ]]; then
  echo "Error: multifile macOS E2E requires CI=true and PMG_MDM_E2E=1" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
INSTALLER="${SCRIPT_DIR}/macos/pmg_setup_install_macos.sh"
UNINSTALLER="${SCRIPT_DIR}/macos/pmg_uninstall_macos.sh"
# The fan-out scenario runs the pmg wrapper as a second user. That user cannot
# traverse the caller's private TMPDIR. /tmp is open to every user.
TEST_ROOT=$(mktemp -d /tmp/pmg-mdm-e2e.XXXXXX)
chmod 0755 "$TEST_ROOT"
# shellcheck source=e2e_lib_macos.sh
source "${BASH_SOURCE[0]%/*}/e2e_lib_macos.sh"

STAGE_DIR="${TEST_ROOT}/staged"
E2E_USER="pmge2e"
E2E_USER_HOME="/Users/${E2E_USER}"
E2E_USER_CONFIG="${E2E_USER_HOME}/Library/Application Support/safedep/pmg/config.yml"

create_pmg_wrapper

cleanup() {
  set +e
  sudo -n sysadminctl -deleteUser "$E2E_USER" >/dev/null 2>&1
  run_uninstaller "$UNINSTALLER" >/dev/null 2>&1
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

test_multifile_configured_install() {
  local pmg_bin

  log "Testing multifile install with a sibling config.yml"
  reset_wrapper_captures
  mkdir -p "$STAGE_DIR"
  # The installer reads a sibling config.yml. Stage it in a temp dir so the
  # repo stays clean and the fan-out scenario can run without a sibling config.
  cp "${SCRIPT_DIR}/lib_macos.sh" "$INSTALLER" "$STAGE_DIR/"
  cat > "${STAGE_DIR}/config.yml" <<'EOF'
paranoid: true
EOF

  sudo -n /usr/bin/env \
    PATH="$WRAPPER_PATH" \
    SAFEDEP_API_KEY="$TEST_API_KEY" \
    SAFEDEP_TENANT_ID="$TEST_TENANT_ID" \
    "${STAGE_DIR}/pmg_setup_install_macos.sh"

  pmg_bin=$(installed_pmg) || fail "multifile installer did not install pmg"
  "$pmg_bin" version >/dev/null
  assert_global_config_installed "${STAGE_DIR}/config.yml"
  assert_absent "$USER_CONFIG"
  assert_equals "true" "$("$pmg_bin" config get paranoid)" \
    "global config value"
  assert_login_recorded
  assert_no_unexpected_cloud

  run_uninstaller "$UNINSTALLER"
  assert_logout_recorded
  assert_no_unexpected_cloud
  assert_uninstalled
}

test_multifile_multi_user_install() {
  local pmg_bin install_output add_output del_output

  log "Testing multifile root fan-out across local users"
  reset_wrapper_captures
  if ! add_output=$(sudo -n sysadminctl -addUser "$E2E_USER" \
    -fullName "PMG MDM E2E" -password "pmg-e2e-password" 2>&1) ||
    ! id "$E2E_USER" >/dev/null 2>&1; then
    printf '%s\n' "$add_output"
    fail "sysadminctl did not create the test user"
  fi
  sudo -n createhomedir -c -u "$E2E_USER" >/dev/null
  sudo -n test -d "$E2E_USER_HOME" ||
    fail "createhomedir did not create the test user home"

  if ! install_output=$(
    sudo -n /usr/bin/env \
      PATH="$WRAPPER_PATH" \
      SAFEDEP_API_KEY="$TEST_API_KEY" \
      SAFEDEP_TENANT_ID="$TEST_TENANT_ID" \
      "$INSTALLER" 2>&1
  ); then
    printf '%s\n' "$install_output"
    fail "multifile installer failed during the fan-out scenario"
  fi
  printf '%s\n' "$install_output"

  pmg_bin=$(installed_pmg) || fail "multifile installer did not install pmg"
  assert_file "$USER_CONFIG"
  assert_file "$E2E_USER_CONFIG"
  assert_owner "$E2E_USER" "$E2E_USER_CONFIG" "second user config owner"
  assert_equals "true" "$("$pmg_bin" config get cloud.enabled)" \
    "cloud configuration"
  # Cloud login runs only for the console user. A login recorded for any other
  # user adds a second identity line and fails assert_login_recorded.
  assert_login_recorded
  [[ "$install_output" == *"${E2E_USER} is not logged in"* ]] ||
    fail "installer did not report the cloud skip for the second user"
  [[ "$install_output" != *"cloud login failed"* ]] ||
    fail "installer reported a cloud login failure"
  assert_no_unexpected_cloud

  run_uninstaller "$UNINSTALLER"
  assert_logout_recorded
  assert_user_state_removed "$E2E_USER_HOME"
  assert_no_unexpected_cloud
  assert_uninstalled

  if ! del_output=$(sudo -n sysadminctl -deleteUser "$E2E_USER" 2>&1) ||
    id "$E2E_USER" >/dev/null 2>&1; then
    printf '%s\n' "$del_output"
    fail "sysadminctl did not delete the test user"
  fi
}

require_e2e_preconditions
run_uninstaller "$UNINSTALLER"
assert_no_unexpected_cloud
assert_uninstalled

test_multifile_configured_install
test_multifile_multi_user_install
echo "PASS"
