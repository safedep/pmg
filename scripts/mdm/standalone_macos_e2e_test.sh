#!/bin/bash
set -euo pipefail

if [[ "${CI:-}" != "true" || "${PMG_MDM_E2E:-}" != "1" ]]; then
  echo "Error: standalone macOS E2E requires CI=true and PMG_MDM_E2E=1" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
GENERATOR="${SCRIPT_DIR}/generate_standalone_scripts.sh"
INSTALLER="${SCRIPT_DIR}/standalone/pmg_setup_install_macos_standalone.sh"
UNINSTALLER="${SCRIPT_DIR}/standalone/pmg_uninstall_macos_standalone.sh"
TEST_ROOT=$(mktemp -d)
CONFIG="${TEST_ROOT}/config.yml"
CONFIGURED_OUTPUT="${TEST_ROOT}/configured"
CREDENTIAL_OUTPUT="${TEST_ROOT}/credentials"
PMG_WRAPPER_DIR="${TEST_ROOT}/pmg-wrapper"
PMG_WRAPPER="${PMG_WRAPPER_DIR}/pmg"
LOGIN_ARGS="${PMG_WRAPPER_DIR}/cloud-login.args"
LOGIN_ENV="${PMG_WRAPPER_DIR}/cloud-login.env"
LOGIN_IDENTITY="${PMG_WRAPPER_DIR}/cloud-login.identity"
LOGOUT_ARGS="${PMG_WRAPPER_DIR}/cloud-logout.args"
UNEXPECTED_CLOUD="${PMG_WRAPPER_DIR}/unexpected-cloud.args"
WRAPPER_PATH="${PMG_WRAPPER_DIR}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
GLOBAL_CONFIG="/Library/Application Support/safedep/pmg/config.yml"
USER_CONFIG="${HOME}/Library/Application Support/safedep/pmg/config.yml"
TEST_API_KEY="pmg-mdm-e2e-api-key"
TEST_TENANT_ID="pmg-mdm-e2e-tenant"
EXPECTED_USER=$(id -un)
EXPECTED_UID=$(id -u)
EXPECTED_HOME="$HOME"
CONSOLE_USER=$(stat -f '%Su' /dev/console)
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

create_pmg_wrapper() {
  mkdir -p "$PMG_WRAPPER_DIR"
  cat > "$PMG_WRAPPER" <<'EOF'
#!/bin/bash
set -euo pipefail

WRAPPER_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

if [[ "${1:-}" == "cloud" ]]; then
  if [[ "$#" -eq 3 && "${2:-}" == "login" &&
    "${3:-}" == "--from-env" ]]; then
    printf '%s\n' "$@" > "${WRAPPER_DIR}/cloud-login.args"
    printf '%s\t%s\n' "${SAFEDEP_API_KEY:-}" "${SAFEDEP_TENANT_ID:-}" \
      > "${WRAPPER_DIR}/cloud-login.env"
    printf '%s\t%s\t%s\n' "$(id -u)" "$(id -un)" "$HOME" \
      > "${WRAPPER_DIR}/cloud-login.identity"
    exit 0
  fi
  if [[ "$#" -eq 2 && "${2:-}" == "logout" ]]; then
    printf '%s\n' "$@" > "${WRAPPER_DIR}/cloud-logout.args"
    exit 0
  fi
  printf '%s\n' "$@" >> "${WRAPPER_DIR}/unexpected-cloud.args"
  exit 1
fi

for real_pmg in /usr/local/bin/pmg /opt/homebrew/bin/pmg; do
  if [[ -x "$real_pmg" ]]; then
    exec "$real_pmg" "$@"
  fi
done

if [[ "$#" -eq 2 && "${1:-}" == "setup" &&
  "${2:-}" == "remove" ]]; then
  exit 0
fi

echo "Error: installed pmg binary not found" >&2
exit 1
EOF
  chmod 0755 "$PMG_WRAPPER"
}

run_uninstaller() {
  local uninstaller="$1"

  sudo -n /usr/bin/env PATH="$WRAPPER_PATH" "$uninstaller"
}

create_pmg_wrapper

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
  run_uninstaller "$UNINSTALLER" >/dev/null 2>&1
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

  run_uninstaller "$UNINSTALLER"
  assert_absent "$UNEXPECTED_CLOUD"
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
  cat > "${CONFIGURED_OUTPUT}/config.yml" <<'EOF'
paranoid: false
EOF

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

  run_uninstaller "$configured_uninstaller"
  assert_absent "$UNEXPECTED_CLOUD"
  assert_uninstalled
}

test_cloud_credentials_install() {
  local pmg_bin

  log "Testing embedded cloud credentials"
  SAFEDEP_API_KEY="$TEST_API_KEY" \
    SAFEDEP_TENANT_ID="$TEST_TENANT_ID" \
    "$GENERATOR" \
    --embed-cloud-credentials \
    --output-dir "$CREDENTIAL_OUTPUT"

  local credential_installer="${CREDENTIAL_OUTPUT}/pmg_setup_install_macos_standalone.sh"
  local credential_uninstaller="${CREDENTIAL_OUTPUT}/pmg_uninstall_macos_standalone.sh"

  sudo -n /usr/bin/env \
    PATH="$WRAPPER_PATH" \
    "$credential_installer"
  pmg_bin=$(installed_pmg) || fail "credential installer did not install pmg"
  assert_file "$LOGIN_ARGS"
  assert_file "$LOGIN_ENV"
  assert_file "$LOGIN_IDENTITY"
  assert_equals $'cloud\nlogin\n--from-env' "$(cat "$LOGIN_ARGS")" \
    "cloud login argv"
  assert_equals "${TEST_API_KEY}"$'\t'"${TEST_TENANT_ID}" \
    "$(cat "$LOGIN_ENV")" "cloud login environment"
  assert_equals "${EXPECTED_UID}"$'\t'"${EXPECTED_USER}"$'\t'"${EXPECTED_HOME}" \
    "$(cat "$LOGIN_IDENTITY")" "cloud login user context"
  assert_absent "$UNEXPECTED_CLOUD"
  assert_equals "true" "$("$pmg_bin" config get cloud.enabled)" \
    "cloud configuration"

  run_uninstaller "$credential_uninstaller"
  assert_file "$LOGOUT_ARGS"
  assert_equals $'cloud\nlogout' "$(cat "$LOGOUT_ARGS")" \
    "cloud logout argv"
  assert_absent "$UNEXPECTED_CLOUD"
  assert_uninstalled
}

[[ "$EXPECTED_UID" -ne 0 ]] || fail "macOS E2E must run from a non-root user"
assert_equals "$EXPECTED_USER" "$CONSOLE_USER" \
  "macOS E2E current and console user"
sudo -n true || fail "passwordless sudo is required"
run_uninstaller "$UNINSTALLER"
assert_absent "$UNEXPECTED_CLOUD"
assert_uninstalled

test_standalone_release_install
test_configured_install
test_cloud_credentials_install
echo "PASS"
