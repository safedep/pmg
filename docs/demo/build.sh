#!/bin/bash

# Use vhs, ffmpeg, a current native pmg, npm, and Node on PATH.
# Use a supported sandbox host for pmg-sandbox.tape.
# The tapes run setup, edit shell startup files, and use live npm and analysis APIs.
# Copy docs/demo and docs/assets into a scratch tree before running this script.
# Use an isolated disposable HOME. The script runs commands from its own directory.
# Set PMG_CONFIG_DIR and PMG_CACHE_DIR under that HOME before recording.
# Disable cloud sync and telemetry for a local recording.
# The sandbox tape enables sandboxing visibly and shows its CI=true setting.
# An accepted machine-managed config can still override these user settings.

# Check if vhs is installed
if ! command -v vhs &> /dev/null; then
    echo "vhs could not be found"
    exit 1
fi

# Switch to the script directory
cd "$(dirname "$0")"

# Enumerate all .tape files in the current directory
for file in *.tape; do
    vhs "$file"
done