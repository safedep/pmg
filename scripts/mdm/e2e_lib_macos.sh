#!/bin/bash
# e2e_lib_macos.sh — shared helpers for the macOS MDM E2E test scripts.
# Set TEST_ROOT before you source this file. Test-only; not part of any
# deployment package.
# shellcheck disable=SC2034

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: the macOS E2E tests run on macOS only" >&2
  exit 1
fi

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

# The wrapper shadows pmg on PATH. It records cloud login/logout calls instead
# of reaching SafeDep Cloud, and forwards everything else to the installed
# binary. The wrapper directory is world-readable so root fan-out can run it
# as other local users.
create_pmg_wrapper() {
  mkdir -p "$PMG_WRAPPER_DIR"
  chmod 0755 "$PMG_WRAPPER_DIR"
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

# Remove the login/logout captures so a scenario cannot pass on a stale file.
# unexpected-cloud.args stays: any unexpected call must fail the test.
reset_wrapper_captures() {
  rm -f "$LOGIN_ARGS" "$LOGIN_ENV" "$LOGIN_IDENTITY" "$LOGOUT_ARGS"
}

run_uninstaller() {
  local uninstaller="$1"

  sudo -n /usr/bin/env PATH="$WRAPPER_PATH" "$uninstaller"
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

require_e2e_preconditions() {
  [[ "$EXPECTED_UID" -ne 0 ]] || fail "macOS E2E must run from a non-root user"
  assert_equals "$EXPECTED_USER" "$CONSOLE_USER" \
    "macOS E2E current and console user"
  sudo -n true || fail "passwordless sudo is required"
}
