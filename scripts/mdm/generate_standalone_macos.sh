#!/bin/bash
# generate_standalone_macos.sh — macOS wrapper for the standalone generator.
# Regenerates standalone/ from lib_macos.sh and the macOS entry scripts.

set -euo pipefail

# Capture and unset the credentials before any child process runs, so they
# never enter the environment and cannot leak to children.
CAPTURED_API_KEY="${SAFEDEP_API_KEY:-}"
CAPTURED_TENANT_ID="${SAFEDEP_TENANT_ID:-}"
unset SAFEDEP_API_KEY SAFEDEP_TENANT_ID

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

STANDALONE_LIB_SOURCE="${SCRIPT_DIR}/macos/lib_macos.sh"
STANDALONE_INSTALL_SOURCE="${SCRIPT_DIR}/macos/pmg_setup_install_macos.sh"
STANDALONE_UNINSTALL_SOURCE="${SCRIPT_DIR}/macos/pmg_uninstall_macos.sh"
STANDALONE_DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}/standalone"
STANDALONE_INSTALL_NAME="pmg_setup_install_macos_standalone.sh"
STANDALONE_UNINSTALL_NAME="pmg_uninstall_macos_standalone.sh"
STANDALONE_GENERATOR="generate_standalone_macos.sh"

# shellcheck source=lib/generate_standalone_lib.sh
source "${SCRIPT_DIR}/lib/generate_standalone_lib.sh"
STANDALONE_CLOUD_API_KEY="$CAPTURED_API_KEY"
STANDALONE_CLOUD_TENANT_ID="$CAPTURED_TENANT_ID"
unset CAPTURED_API_KEY CAPTURED_TENANT_ID
generate_standalone_main "$@"
