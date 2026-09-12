#!/bin/bash
# generate_standalone_windows.sh - Windows wrapper for the standalone generator.
# Regenerates standalone/ from lib_windows.ps1 and the Windows entry scripts.

set -euo pipefail

# Capture and unset the credentials before any child process runs, so they
# never enter the environment and cannot leak to children.
CAPTURED_API_KEY="${SAFEDEP_API_KEY:-}"
CAPTURED_TENANT_ID="${SAFEDEP_TENANT_ID:-}"
unset SAFEDEP_API_KEY SAFEDEP_TENANT_ID

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

STANDALONE_LIB_SOURCE="${SCRIPT_DIR}/windows/lib_windows.ps1"
STANDALONE_INSTALL_SOURCE="${SCRIPT_DIR}/windows/pmg_setup_install_windows.ps1"
STANDALONE_UNINSTALL_SOURCE="${SCRIPT_DIR}/windows/pmg_uninstall_windows.ps1"
STANDALONE_DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}/standalone"
STANDALONE_INSTALL_NAME="pmg_setup_install_windows_standalone.ps1"
STANDALONE_UNINSTALL_NAME="pmg_uninstall_windows_standalone.ps1"
STANDALONE_GENERATOR="generate_standalone_windows.sh"
STANDALONE_MAX_SIZE=200000

# PowerShell has no shebang and no shellcheck directive. The entry scripts
# dot-source the lib, and the uninstaller needs no placeholder for it.
STANDALONE_HEADER=""
STANDALONE_SKIP_LINE=""
# shellcheck disable=SC2016 # literal by design, it matches a line in the entry scripts
STANDALONE_SOURCE_LINE='. "$PSScriptRoot\lib_windows.ps1"'
STANDALONE_UNINSTALL_SOURCE_REPLACEMENT=""

# shellcheck source=lib/generate_standalone_lib.sh
source "${SCRIPT_DIR}/lib/generate_standalone_lib.sh"

generate_standalone_embed_line() {
  printf "\$%s='%s'\n" "$1" "$2"
}

generate_standalone_syntax_check() {
  local powershell
  powershell=$(command -v pwsh || command -v powershell || true)
  if [[ -z "$powershell" ]]; then
    echo "Warning: PowerShell is not available. The generated script was not parsed." >&2
    return
  fi
  # shellcheck disable=SC2016 # PowerShell expands the command.
  "$powershell" -NoProfile -NonInteractive -Command '
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$errors) | Out-Null
    if ($errors) {
      $errors | ForEach-Object { [Console]::Error.WriteLine($_) }
      exit 1
    }
  ' "$1"
}

generate_standalone_credential_permissions_warning() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      echo "Warning: file modes do not protect credentials on this Windows host. Restrict the installer ACL." >&2
      ;;
  esac
}

STANDALONE_CLOUD_API_KEY="$CAPTURED_API_KEY"
STANDALONE_CLOUD_TENANT_ID="$CAPTURED_TENANT_ID"
unset CAPTURED_API_KEY CAPTURED_TENANT_ID
generate_standalone_main "$@"
