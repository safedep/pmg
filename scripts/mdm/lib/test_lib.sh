#!/bin/bash
# test_lib.sh — shared assert helpers for the scripts/mdm test files.
# This file is sourced by the tests; it is not executed directly.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_absent() {
  [[ ! -e "$1" && ! -L "$1" ]] || fail "path unexpectedly exists: $1"
}

assert_executable() {
  [[ -x "$1" ]] || fail "file is not executable: $1"
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

assert_one_shebang() {
  local count
  count=$(grep -c '^#!' "$1" || true)
  [[ "$count" -eq 1 ]] || fail "$1 must contain exactly one shebang"
}

assert_fails() {
  if "$@"; then
    fail "command should fail: $*"
  fi
}

decode_base64() {
  if printf '' | base64 --decode >/dev/null 2>&1; then
    base64 --decode
  else
    base64 -D
  fi
}

encode_base64() {
  base64 | tr -d '\r\n'
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

assert_variant() {
  local variant="$1"
  local installer="$2"
  local uninstaller="$3"
  local has_config="$4"
  local has_credentials="$5"
  local expected_installer_mode="$6"

  echo "Verifying variant: $variant"
  if [[ "$has_config" == "yes" ]]; then
    assert_contains "$installer" "EMBEDDED_GLOBAL_CONFIG_B64='"
  else
    assert_not_contains "$installer" "EMBEDDED_GLOBAL_CONFIG_B64='"
  fi
  if [[ "$has_credentials" == "yes" ]]; then
    assert_contains "$installer" "EMBEDDED_SAFEDEP_API_KEY_B64='"
    assert_contains "$installer" "EMBEDDED_SAFEDEP_TENANT_ID_B64='"
  else
    assert_not_contains "$installer" "EMBEDDED_SAFEDEP_API_KEY_B64='"
    assert_not_contains "$installer" "EMBEDDED_SAFEDEP_TENANT_ID_B64='"
  fi
  assert_not_contains "$uninstaller" "EMBEDDED_GLOBAL_CONFIG_B64='"
  assert_not_contains "$uninstaller" "EMBEDDED_SAFEDEP_API_KEY_B64='"
  assert_not_contains "$uninstaller" "EMBEDDED_SAFEDEP_TENANT_ID_B64='"
  assert_not_contains "$installer" "$TEST_API_KEY"
  assert_not_contains "$installer" "$TEST_TENANT_ID"
  assert_not_contains "$uninstaller" "$TEST_API_KEY"
  assert_not_contains "$uninstaller" "$TEST_TENANT_ID"
  assert_equals "$expected_installer_mode" "$(file_mode "$installer")" \
    "$variant installer mode"
  assert_equals "755" "$(file_mode "$uninstaller")" \
    "$variant uninstaller mode"
}
