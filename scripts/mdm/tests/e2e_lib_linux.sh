#!/bin/bash
# Shared helpers for the Linux MDM E2E test scripts.
# Set TEST_ROOT before you source this file.
# It is test-only. It is not part of any deployment package.
# shellcheck disable=SC2034

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Error: the Linux E2E tests run on Linux only" >&2
  exit 1
fi

PMG_WRAPPER_DIR="${TEST_ROOT}/pmg-wrapper"
PMG_WRAPPER="${PMG_WRAPPER_DIR}/pmg"
LOGIN_ARGS="${PMG_WRAPPER_DIR}/cloud-login.args"
LOGIN_ENV="${PMG_WRAPPER_DIR}/cloud-login.env"
LOGIN_IDENTITY="${PMG_WRAPPER_DIR}/cloud-login.identity"
SYNC_ARGS="${PMG_WRAPPER_DIR}/cloud-sync.args"
SYNC_ENV="${PMG_WRAPPER_DIR}/cloud-sync.env"
SYNC_IDENTITY="${PMG_WRAPPER_DIR}/cloud-sync.identity"
LOGOUT_ARGS="${PMG_WRAPPER_DIR}/cloud-logout.args"
LOGOUT_IDENTITY="${PMG_WRAPPER_DIR}/cloud-logout.identity"
UNEXPECTED_CLOUD="${PMG_WRAPPER_DIR}/unexpected-cloud.args"
CAPTURE_FILES=(
  "$LOGIN_ARGS" "$LOGIN_ENV" "$LOGIN_IDENTITY"
  "$SYNC_ARGS" "$SYNC_ENV" "$SYNC_IDENTITY"
  "$LOGOUT_ARGS" "$LOGOUT_IDENTITY" "$UNEXPECTED_CLOUD"
)
WRAPPER_PATH="${PMG_WRAPPER_DIR}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
GLOBAL_CONFIG="/etc/safedep/pmg/config.yml"
USER_CONFIG="${HOME}/.config/safedep/pmg/config.yml"
TEST_API_KEY="pmg-mdm-e2e-api-key"
TEST_TENANT_ID="pmg-mdm-e2e-tenant"
EXPECTED_USER=$(id -un)
EXPECTED_UID=$(id -u)
EXPECTED_HOME="$HOME"
EXPECTED_IDENTITY="${EXPECTED_UID}"$'\t'"${EXPECTED_USER}"$'\t'"${EXPECTED_HOME}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

log() {
  echo "==> $*"
}

# Assertions run through sudo. A path under a user home with mode 0700 is then
# read correctly. A plain test would report such a path as absent.
assert_file() {
  sudo -n test -f "$1" || fail "missing file: $1"
}

assert_absent() {
  if sudo -n test -e "$1" || sudo -n test -L "$1"; then
    fail "path still exists: $1"
  fi
}

assert_equals() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  [[ "$actual" == "$expected" ]] ||
    fail "$message: expected '$expected', got '$actual'"
}

assert_owner() {
  assert_equals "$1" "$(sudo -n stat -c '%U' "$2")" "$3"
}

# The wrapper shadows pmg on PATH. It records cloud login, sync, and logout calls
# instead of reaching SafeDep Cloud. It forwards every other call to the
# installed binary. The root fan-out runs the wrapper as each local user.
# reset_wrapper_captures pre-creates the capture files world-writable, so the
# wrapper appends its own line as any user. A call made as the wrong user is
# then recorded, not lost.
create_pmg_wrapper() {
  mkdir -p "$PMG_WRAPPER_DIR"
  cat > "$PMG_WRAPPER" <<'EOF'
#!/bin/bash
set -euo pipefail

WRAPPER_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
identity=$(printf '%s\t%s\t%s' "$(id -u)" "$(id -un)" "$HOME")

if [[ "${1:-}" == "cloud" ]]; then
  if [[ "$#" -eq 3 && "${2:-}" == "login" && "${3:-}" == "--from-env" ]]; then
    printf '%s\n' "$@" >> "${WRAPPER_DIR}/cloud-login.args"
    printf '%s\t%s\n' "${SAFEDEP_API_KEY:-}" "${SAFEDEP_TENANT_ID:-}" \
      >> "${WRAPPER_DIR}/cloud-login.env"
    printf '%s\n' "$identity" >> "${WRAPPER_DIR}/cloud-login.identity"
    exit 0
  fi
  if [[ "$#" -eq 2 && "${2:-}" == "logout" ]]; then
    printf '%s\n' "$@" >> "${WRAPPER_DIR}/cloud-logout.args"
    printf '%s\n' "$identity" >> "${WRAPPER_DIR}/cloud-logout.identity"
    exit 0
  fi
  if [[ "$#" -eq 4 && "${2:-}" == "sync" &&
    "${3:-}" == "--timeout" && "${4:-}" == "1m" ]]; then
    printf '%s\n' "$*" >> "${WRAPPER_DIR}/cloud-sync.args"
    printf '%s\t%s\n' "${SAFEDEP_API_KEY:-}" "${SAFEDEP_TENANT_ID:-}" \
      >> "${WRAPPER_DIR}/cloud-sync.env"
    printf '%s\n' "$identity" >> "${WRAPPER_DIR}/cloud-sync.identity"
    exit 0
  fi
  printf '%s\t%s\n' "$identity" "$*" >> "${WRAPPER_DIR}/unexpected-cloud.args"
  exit 1
fi

for real_pmg in /usr/local/bin/pmg; do
  if [[ -x "$real_pmg" ]]; then
    exec "$real_pmg" "$@"
  fi
done

if [[ "$#" -eq 2 && "${1:-}" == "setup" && "${2:-}" == "remove" ]]; then
  exit 0
fi

echo "Error: installed pmg binary not found" >&2
exit 1
EOF
  chmod 0755 "$PMG_WRAPPER"
  reset_wrapper_captures
}

# Truncate the capture files and make them world-writable, so the wrapper can
# append as any local user during the root fan-out. A scenario starts clean.
reset_wrapper_captures() {
  local capture
  for capture in "${CAPTURE_FILES[@]}"; do
    : > "$capture"
    chmod 0666 "$capture"
  done
}

# Assert that the uninstaller removed every per-user artifact for the given
# home. It mirrors remove_user_state in pmg_uninstall_linux.sh. This makes the
# end-of-scenario teardown a real reset boundary, not an assumed one.
assert_user_state_removed() {
  local home="$1"
  assert_absent "${home}/.config/safedep/pmg"
  assert_absent "${home}/.cache/safedep/pmg"
  assert_absent "${home}/.local/share/safedep/pmg"
  assert_absent "${home}/.pmg"
  assert_absent "${home}/.pmg.rc"
  assert_absent "${home}/.local/bin/pmg"
}

assert_login_recorded() {
  assert_equals $'cloud\nlogin\n--from-env' "$(cat "$LOGIN_ARGS")" \
    "cloud login argv"
  assert_equals "${TEST_API_KEY}"$'\t'"${TEST_TENANT_ID}" \
    "$(cat "$LOGIN_ENV")" "cloud login environment"
  assert_equals "$EXPECTED_IDENTITY" "$(cat "$LOGIN_IDENTITY")" \
    "cloud login user context"
}

assert_logout_recorded() {
  assert_equals $'cloud\nlogout' "$(cat "$LOGOUT_ARGS")" "cloud logout argv"
  assert_equals "$EXPECTED_IDENTITY" "$(cat "$LOGOUT_IDENTITY")" \
    "cloud logout user context"
}

assert_sync_recorded_for() {
  grep -Fqx "$1" "$SYNC_IDENTITY" ||
    fail "cloud sync did not run as expected identity: $1"
  grep -Fqx "cloud sync --timeout 1m" "$SYNC_ARGS" ||
    fail "cloud sync argv was not recorded"
  grep -Fqx "${TEST_API_KEY}"$'\t'"${TEST_TENANT_ID}" "$SYNC_ENV" ||
    fail "cloud sync credentials were not recorded"
}

assert_no_login_recorded() {
  [[ ! -s "$LOGIN_ARGS" ]] || fail "unexpected cloud login: $(cat "$LOGIN_ARGS")"
}

assert_no_sync_recorded() {
  [[ ! -s "$SYNC_ARGS" ]] || fail "unexpected cloud sync: $(cat "$SYNC_ARGS")"
}

assert_no_unexpected_cloud() {
  [[ ! -s "$UNEXPECTED_CLOUD" ]] ||
    fail "unexpected cloud call: $(cat "$UNEXPECTED_CLOUD")"
}

assert_global_config_installed() {
  local src="$1"
  assert_file "$GLOBAL_CONFIG"
  sudo -n cmp "$src" "$GLOBAL_CONFIG" || fail "global config does not match $src"
  assert_owner "root" "$GLOBAL_CONFIG" "global config owner"
  assert_equals "644" "$(sudo -n stat -c '%a' "$GLOBAL_CONFIG")" \
    "global config mode"
}

run_uninstaller() {
  local uninstaller="$1"

  sudo -n /usr/bin/env PATH="$WRAPPER_PATH" "$uninstaller"
}

installed_pmg() {
  if [[ -x /usr/local/bin/pmg ]]; then
    printf '%s\n' /usr/local/bin/pmg
    return 0
  fi
  return 1
}

assert_uninstalled() {
  assert_absent /usr/local/bin/pmg
  assert_absent "$GLOBAL_CONFIG"
  assert_user_state_removed "$HOME"
}

require_e2e_preconditions() {
  [[ "$EXPECTED_UID" -ne 0 ]] || fail "Linux E2E must run from a non-root user"
  sudo -n true || fail "passwordless sudo is required"

  # On CI runners without a logind session, create a real Unix domain socket
  # at the session bus path so user_has_session reports a session for the
  # current user. The wrapper already intercepts cloud calls, so the socket
  # is only a gate, not a D-Bus connection.
  if [[ ! -S "/run/user/${EXPECTED_UID}/bus" ]]; then
    sudo -n mkdir -p "/run/user/${EXPECTED_UID}"
    sudo -n python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.bind('/run/user/${EXPECTED_UID}/bus')"
    sudo -n chown "${EXPECTED_UID}:${EXPECTED_UID}" "/run/user/${EXPECTED_UID}/bus"
  fi
}
