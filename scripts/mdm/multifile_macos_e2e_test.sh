#!/bin/bash
# multifile_macos_e2e_test.sh — run the multi-file MDM scripts end to end on a
# disposable macOS CI runner. Uses dummy cloud credentials; a pmg wrapper on
# PATH records cloud login/logout instead of reaching SafeDep Cloud.
set -euo pipefail

if [[ "${CI:-}" != "true" || "${PMG_MDM_E2E:-}" != "1" ]]; then
  echo "Error: multifile macOS E2E requires CI=true and PMG_MDM_E2E=1" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
INSTALLER="${SCRIPT_DIR}/pmg_setup_install_macos.sh"
UNINSTALLER="${SCRIPT_DIR}/pmg_uninstall_macos.sh"
# The fan-out scenario runs the pmg wrapper as a second user, and that user
# cannot traverse the caller's private TMPDIR. /tmp is open to every user.
TEST_ROOT=$(mktemp -d /tmp/pmg-mdm-e2e.XXXXXX)
chmod 0755 "$TEST_ROOT"
# shellcheck source=e2e_lib_macos.sh
source "${SCRIPT_DIR}/e2e_lib_macos.sh"

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
  cp "${SCRIPT_DIR}/lib_macos.sh" "$INSTALLER" "$UNINSTALLER" "$STAGE_DIR/"
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
  assert_file "$GLOBAL_CONFIG"
  cmp "${STAGE_DIR}/config.yml" "$GLOBAL_CONFIG"
  assert_equals "root" "$(stat -f '%Su' "$GLOBAL_CONFIG")" \
    "global config owner"
  assert_equals "644" "$(stat -f '%Lp' "$GLOBAL_CONFIG")" \
    "global config mode"
  assert_absent "$USER_CONFIG"
  assert_equals "true" "$("$pmg_bin" config get paranoid)" \
    "global config value"
  assert_file "$LOGIN_ARGS"
  assert_equals $'cloud\nlogin\n--from-env' "$(cat "$LOGIN_ARGS")" \
    "cloud login argv"
  assert_equals "${TEST_API_KEY}"$'\t'"${TEST_TENANT_ID}" \
    "$(cat "$LOGIN_ENV")" "cloud login environment"
  assert_equals "${EXPECTED_UID}"$'\t'"${EXPECTED_USER}"$'\t'"${EXPECTED_HOME}" \
    "$(cat "$LOGIN_IDENTITY")" "cloud login user context"
  assert_absent "$UNEXPECTED_CLOUD"

  run_uninstaller "${STAGE_DIR}/pmg_uninstall_macos.sh"
  assert_file "$LOGOUT_ARGS"
  assert_equals $'cloud\nlogout' "$(cat "$LOGOUT_ARGS")" \
    "cloud logout argv"
  assert_absent "$UNEXPECTED_CLOUD"
  assert_uninstalled
}

test_multifile_multi_user_install() {
  local pmg_bin install_output

  log "Testing multifile root fan-out across local users"
  reset_wrapper_captures
  sudo -n sysadminctl -addUser "$E2E_USER" -fullName "PMG MDM E2E" \
    -password "pmg-e2e-password" >/dev/null 2>&1
  id "$E2E_USER" >/dev/null 2>&1 || fail "could not create test user"
  sudo -n createhomedir -c -u "$E2E_USER" >/dev/null
  [[ -d "$E2E_USER_HOME" ]] || fail "test user home was not created"

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
  assert_equals "$E2E_USER" "$(stat -f '%Su' "$E2E_USER_CONFIG")" \
    "second user config owner"
  assert_equals "true" "$("$pmg_bin" config get cloud.enabled)" \
    "cloud configuration"
  assert_equals "${EXPECTED_UID}"$'\t'"${EXPECTED_USER}"$'\t'"${EXPECTED_HOME}" \
    "$(cat "$LOGIN_IDENTITY")" "cloud login ran for the console user only"
  [[ "$install_output" == *"${E2E_USER} is not logged in"* ]] ||
    fail "installer did not report the cloud skip for the second user"
  assert_absent "$UNEXPECTED_CLOUD"

  run_uninstaller "$UNINSTALLER"
  assert_file "$LOGOUT_ARGS"
  assert_equals $'cloud\nlogout' "$(cat "$LOGOUT_ARGS")" \
    "cloud logout argv"
  assert_absent "$E2E_USER_CONFIG"
  assert_absent "$UNEXPECTED_CLOUD"
  assert_uninstalled

  sudo -n sysadminctl -deleteUser "$E2E_USER" >/dev/null 2>&1 ||
    fail "could not delete test user"
}

require_e2e_preconditions
run_uninstaller "$UNINSTALLER"
assert_absent "$UNEXPECTED_CLOUD"
assert_uninstalled

test_multifile_configured_install
test_multifile_multi_user_install
echo "PASS"
