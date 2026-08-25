#!/bin/bash
# pmg_setup_install_test.sh — test the installer's internals for every OS.
# Extracts functions from pmg_setup_install_<os>.sh and exercises them with
# mocked helpers. Runs the same assertions for macos and linux.
# shellcheck disable=SC1090,SC2034,SC2317,SC2329,SC2016
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

run_installer_tests() {
    local os="$1"
    local os_uname="$2"
    local fake_user_entry="$3"
    local skip_msg="$4"

    local INSTALL_SOURCE="${SCRIPT_DIR}/${os}/pmg_setup_install_${os}.sh"
    local LIB_SOURCE="${SCRIPT_DIR}/${os}/lib_${os}.sh"
    local TEST_ROOT
    TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/pmg-install-test.XXXXXX")
    trap 'rm -rf "$TEST_ROOT"' RETURN

    local INSTALL_TAIL="${TEST_ROOT}/install_tail.sh"
    local CONFIG_RUNTIME="${TEST_ROOT}/config_runtime.sh"
    local CREDENTIAL_RUNTIME="${TEST_ROOT}/credential_runtime.sh"
    local STARTUP_RUNTIME="${TEST_ROOT}/pmg_setup_install_${os}.sh"
    local STARTUP_PROBE_BIN="${TEST_ROOT}/startup-probe-bin"
    local STARTUP_ENV_LEAK_FILE="${TEST_ROOT}/startup-env-leak"
    local STARTUP_CHILD_TRACE_FILE="${TEST_ROOT}/startup-child-trace"
    local STARTUP_CREDENTIALS_FILE="${TEST_ROOT}/startup-credentials"
  local STARTUP_UNAME_FILE="${TEST_ROOT}/startup-uname"
    local FAKE_PMG="${TEST_ROOT}/pmg"

    echo "==> Testing pmg_setup_install_${os}.sh"

  fail() {
    echo "FAIL: $*" >&2
    exit 1
  }

  assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="$3"
    [[ "$actual" == "$expected" ]] ||
      fail "$message: expected '$expected', got '$actual'"
  }

  assert_contains() {
    grep -Fq "$2" "$1" || fail "$1 does not contain: $2"
  }

  assert_not_contains() {
    local status
    if grep -Fq "$2" "$1"; then
      fail "$1 unexpectedly contains: $2"
    else
      status=$?
      [[ "$status" -eq 1 ]] || fail "could not inspect file: $1"
    fi
  }

  cat > "$FAKE_PMG" <<'EOF'
#!/bin/bash
printf '%s\n' "$@" > "$PMG_LOGIN_ARGS_FILE"
printf '%s\t%s\n' "$SAFEDEP_API_KEY" "$SAFEDEP_TENANT_ID" \
  > "$PMG_LOGIN_CREDENTIALS_FILE"
exit "$PMG_LOGIN_STATUS"
EOF
  chmod 0755 "$FAKE_PMG"

  cp "$LIB_SOURCE" "${TEST_ROOT}/lib_${os}.sh"
  awk '
    /^set -euo pipefail$/ { emit = 1 }
    emit { print }
    emit && /^load_embedded_cloud_credentials \|\| exit 1$/ { exit }
  ' "$INSTALL_SOURCE" > "$STARTUP_RUNTIME"

  [[ -s "$STARTUP_RUNTIME" ]] ||
    fail "startup extraction matched nothing in $INSTALL_SOURCE (anchor moved?)"

  cat >> "$STARTUP_RUNTIME" <<'EOF'
printf 'CLOUD_API_KEY=%s\nCLOUD_TENANT_ID=%s\n' \
  "$CLOUD_API_KEY" "$CLOUD_TENANT_ID" > "$STARTUP_CREDENTIALS_FILE"
EOF

  mkdir -p "$STARTUP_PROBE_BIN"
  cat > "${STARTUP_PROBE_BIN}/probe" <<'EOF'
#!/bin/bash
printf '%s\n' "${0##*/}" >> "$STARTUP_CHILD_TRACE_FILE"
if [[ -n "${SAFEDEP_API_KEY+x}" || -n "${SAFEDEP_TENANT_ID+x}" ||
  -n "${CLOUD_API_KEY+x}" || -n "${CLOUD_TENANT_ID+x}" ]]; then
  printf '%s\n' "${0##*/}" >> "$STARTUP_ENV_LEAK_FILE"
fi
if [[ "${0##*/}" == "uname" ]]; then
  cat "$STARTUP_UNAME_FILE"
  exit 0
fi
real_command="/usr/bin/${0##*/}"
[[ -x "$real_command" ]] || real_command="/bin/${0##*/}"
[[ -x "$real_command" ]] || exit 1
exec "$real_command" "$@"
EOF
  printf '%s\n' "$os_uname" > "$STARTUP_UNAME_FILE"
  for command in dirname uname; do
    cp "${STARTUP_PROBE_BIN}/probe" "${STARTUP_PROBE_BIN}/${command}"
    chmod 0755 "${STARTUP_PROBE_BIN}/${command}"
  done

  env \
    PATH="${STARTUP_PROBE_BIN}:${PATH}" \
    STARTUP_ENV_LEAK_FILE="$STARTUP_ENV_LEAK_FILE" \
    STARTUP_CHILD_TRACE_FILE="$STARTUP_CHILD_TRACE_FILE" \
    STARTUP_CREDENTIALS_FILE="$STARTUP_CREDENTIALS_FILE" \
  STARTUP_UNAME_FILE="$STARTUP_UNAME_FILE" \
    SAFEDEP_API_KEY="startup-api-key" \
    SAFEDEP_TENANT_ID="startup-tenant" \
    /bin/bash "$STARTUP_RUNTIME"
  assert_contains "$STARTUP_CHILD_TRACE_FILE" "dirname"
  assert_contains "$STARTUP_CHILD_TRACE_FILE" "uname"
  [[ ! -e "$STARTUP_ENV_LEAK_FILE" ]] ||
    fail "installer startup child inherited credentials: $(tr '\n' ' ' < "$STARTUP_ENV_LEAK_FILE")"
  [[ -f "$STARTUP_CREDENTIALS_FILE" ]] ||
    fail "installer startup did not capture cloud credentials"
  assert_equals $'CLOUD_API_KEY=startup-api-key\nCLOUD_TENANT_ID=startup-tenant' \
    "$(cat "$STARTUP_CREDENTIALS_FILE")" \
    "installer startup cloud credentials"

  awk '
    /^install_requested_global_config\(\)/ { emit = 1 }
    emit { print }
    emit && /^install_requested_global_config$/ { exit }
  ' "$INSTALL_SOURCE" > "$CONFIG_RUNTIME"

  [[ -s "$CONFIG_RUNTIME" ]] ||
    fail "installer must own embedded config decoding and installation"

  awk '
    /^CLOUD_API_KEY=/ { emit = 1 }
    emit { print }
    emit && /^load_embedded_cloud_credentials \|\| exit 1$/ { exit }
  ' "$INSTALL_SOURCE" > "$CREDENTIAL_RUNTIME"

  [[ -s "$CREDENTIAL_RUNTIME" ]] ||
    fail "installer must own embedded credential decoding"
  assert_not_contains "$CREDENTIAL_RUNTIME" "mktemp"
  assert_not_contains "$CREDENTIAL_RUNTIME" "pmg-embedded-credentials"
  assert_contains "$CREDENTIAL_RUNTIME" \
    "unset EMBEDDED_SAFEDEP_API_KEY_B64 EMBEDDED_SAFEDEP_TENANT_ID_B64"

  awk '/^(cloud_login|configure_user)\(\)/ { emit = 1 } emit' \
    "$INSTALL_SOURCE" > "$INSTALL_TAIL"

  [[ -s "$INSTALL_TAIL" ]] ||
    fail "tail extraction matched nothing in $INSTALL_SOURCE (function renamed?)"

  encode_base64() {
    base64 | tr -d '\r\n'
  }

  run_credential_runtime() {
    local runtime_api_key="$1"
    local runtime_tenant_id="$2"
    local embedded_api_key="$3"
    local embedded_tenant_id="$4"

    (
      set -euo pipefail
      SAFEDEP_API_KEY="$runtime_api_key"
      SAFEDEP_TENANT_ID="$runtime_tenant_id"
      EMBEDDED_SAFEDEP_API_KEY_B64="$embedded_api_key"
      EMBEDDED_SAFEDEP_TENANT_ID_B64="$embedded_tenant_id"

      # Stub uname so require_<os> passes on any host.
      uname() { printf '%s\n' "$os_uname"; }
      export -f uname

      source "$CREDENTIAL_RUNTIME"

      [[ -z "${SAFEDEP_API_KEY+x}" ]] ||
        fail "runtime API key input must be unset after loading"
      [[ -z "${SAFEDEP_TENANT_ID+x}" ]] ||
        fail "runtime tenant ID input must be unset after loading"
      [[ -z "${EMBEDDED_SAFEDEP_API_KEY_B64+x}" ]] ||
        fail "embedded API key must be unset after loading"
      [[ -z "${EMBEDDED_SAFEDEP_TENANT_ID_B64+x}" ]] ||
        fail "embedded tenant ID must be unset after loading"
      printf '%s\t%s\n' "$CLOUD_API_KEY" "$CLOUD_TENANT_ID"
    )
  }

  embedded_api_key=$(printf '%s' "embedded-api-key" | encode_base64)
  embedded_tenant_id=$(printf '%s' "embedded-tenant" | encode_base64)
  runtime_credentials=$(
    run_credential_runtime \
      "runtime-api-key" \
      "runtime-tenant" \
      "$embedded_api_key" \
      "$embedded_tenant_id"
  )
  assert_equals $'runtime-api-key\truntime-tenant' "$runtime_credentials" \
    "complete runtime credential precedence"

  if [[ "$(uname -s)" == "$os_uname" ]]; then
    embedded_credentials=$(
      run_credential_runtime "" "" "$embedded_api_key" "$embedded_tenant_id"
    )
    assert_equals $'embedded-api-key\tembedded-tenant' "$embedded_credentials" \
      "embedded credential decoding"
  fi

  assert_config_install() {
    local embedded_config="$1"
    local adjacent_config="$2"
    local expected_config="$3"
    local case_dir="${TEST_ROOT}/config-$4"
    local captured_config="${case_dir}/captured.yml"
    local encoded_config=""

    mkdir -p "$case_dir"
    printf '%s\n' "$adjacent_config" > "${case_dir}/config.yml"
    if [[ -n "$embedded_config" ]]; then
      encoded_config=$(printf '%s\n' "$embedded_config" | encode_base64)
    fi

    (
      set -euo pipefail
      SCRIPT_DIR="$case_dir"
      GLOBAL_CONFIG_FILE="${case_dir}/global.yml"
      EMBEDDED_GLOBAL_CONFIG_B64="$encoded_config"
      TMPDIR="$case_dir"

      warn() { :; }
      install_global_config() {
        cp "$1" "$captured_config"
      }

      # Stub uname so require_<os> passes on any host.
      uname() { printf '%s\n' "$os_uname"; }
      export -f uname

      source "$CONFIG_RUNTIME"
    )

    assert_equals "$expected_config" "$(cat "$captured_config")" \
      "installed config"
  }

  assert_config_install \
    "source: embedded" \
    "source: adjacent" \
    "source: embedded" \
    "embedded-precedence"

  assert_config_install \
    "" \
    "source: adjacent" \
    "source: adjacent" \
    "adjacent-fallback"

  run_install_tail() {
    local credentials="$1"
    local users="$2"
    local setup_status="$3"
    local session_status="$4"
    local cloud_login_status="${5:-0}"

    (
      set -euo pipefail
      PMG_BIN="$FAKE_PMG"
      GLOBAL_CONFIG_FILE="${TEST_ROOT}/global-config.yml"
      PMG_LOGIN_ARGS_FILE="${TEST_ROOT}/cloud-login.args"
      PMG_LOGIN_CREDENTIALS_FILE="${TEST_ROOT}/cloud-login.credentials"
      PMG_LOGIN_STATUS="$cloud_login_status"
      export PMG_LOGIN_ARGS_FILE PMG_LOGIN_CREDENTIALS_FILE PMG_LOGIN_STATUS
      rm -f "$PMG_LOGIN_ARGS_FILE" "$PMG_LOGIN_CREDENTIALS_FILE"
      if [[ "$credentials" == "yes" ]]; then
        CLOUD_API_KEY="test-api-key"
        CLOUD_TENANT_ID="test-tenant"
      else
        CLOUD_API_KEY=""
        CLOUD_TENANT_ID=""
      fi

      log() { printf 'log:%s\n' "$*"; }
      warn() { printf 'warning:%s\n' "$*"; }
      run_user_file() { return "$setup_status"; }
      user_has_session() { return "$session_status"; }
      run_user_session() {
        assert_equals "test-user" "$1" "cloud login user"
        shift
        local arg
        for arg in "$@"; do
          [[ "$arg" != *"test-api-key"* ]] ||
            fail "cloud login argv contains the API key"
          [[ "$arg" != *"test-tenant"* ]] ||
            fail "cloud login argv contains the tenant ID"
        done
        "$@"
      }
      each_target_user() {
        if [[ "$users" == "yes" ]]; then
          printf '%s\n' "$fake_user_entry"
        fi
      }

      source "$INSTALL_TAIL"
      if [[ "$credentials" == "yes" && "$users" == "yes" &&
        "$setup_status" -eq 0 && "$session_status" -eq 0 ]]; then
        assert_equals $'cloud\nlogin\n--from-env' \
          "$(cat "$PMG_LOGIN_ARGS_FILE")" \
          "cloud login command"
        assert_equals $'test-api-key\ttest-tenant' \
          "$(cat "$PMG_LOGIN_CREDENTIALS_FILE")" \
          "cloud login environment"
        if [[ "$cloud_login_status" -ne 0 ]]; then
          printf 'cloud-login-attempted:%s\n' "$cloud_login_status"
        fi
      fi
      [[ -z "${CLOUD_API_KEY+x}" ]] ||
        fail "cloud API key must be unset after user configuration"
      [[ -z "${CLOUD_TENANT_ID+x}" ]] ||
        fail "cloud tenant ID must be unset after user configuration"
    )
  }

  inactive_output=$(run_install_tail yes yes 0 1) ||
    fail "cloud credentials without a user session should be skipped"
  [[ "$inactive_output" == *"$skip_msg"* ]] ||
    fail "inactive user credential skip must be reported"

  run_install_tail yes no 0 0 ||
    fail "cloud credentials without a target user should be skipped"

  run_install_tail yes yes 0 0 ||
    fail "successful cloud login in an active user session should succeed"

  cloud_login_output=$(run_install_tail yes yes 0 0 1) ||
    fail "failed cloud login should remain nonfatal"
  [[ "$cloud_login_output" == *"cloud-login-attempted:1"* ]] ||
    fail "failed cloud login was not exercised"
  [[ "$cloud_login_output" == *"warning:cloud login failed for test-user"* ]] ||
    fail "failed cloud login must be reported"

  run_install_tail no yes 0 0 ||
    fail "successful setup without cloud credentials should succeed"

  assert_contains "$INSTALL_TAIL" 'exec "$1" cloud login --from-env'
}

run_installer_tests macos Darwin $'test-user\t501\t/Users/test-user' "not logged in"
run_installer_tests linux Linux $'test-user\t1001\t/home/test-user' "no active session"

echo "PASS"
