#!/bin/sh
# Installs the PMG shims and puts their directory on PATH.
set -eu
pmg setup install

# The shim directory depends on the installed pmg version: releases
# before the XDG layout use ~/.pmg/bin, later ones use the data dir.
# This action installs a published release, which may be either, so
# add whichever the install actually created. The action runs on Linux
# only, so the XDG default needs no platform branch.
found=""
for dir in "${XDG_DATA_HOME:-$HOME/.local/share}/safedep/pmg/bin" "$HOME/.pmg/bin"; do
  if [ -d "$dir" ]; then
    printf '%s\n' "$dir" >> "$GITHUB_PATH"
    found="$dir"
  fi
done
if [ -z "$found" ]; then
  printf '%s\n' "::error::No PMG shim directory found after setup install." >&2
  exit 1
fi

# Fetch the cloud policy now, as `pmg proxy start` does in server mode,
# so the first package manager command of the job applies it. The step
# fails when no cloud policy applies. The fetch takes 15 seconds at most:
# 5 seconds for the sync lock and 10 seconds for the fetch. A PMG release
# without --require-policy runs the full sync, and a failure only warns.
if [ "${PMG_CLOUD_ENABLED:-}" = "true" ]; then
  if pmg cloud sync --help 2>/dev/null | grep -q -- '--require-policy'; then
    pmg cloud sync --require-policy
  elif ! pmg cloud sync --timeout 10s; then
    printf '%s\n' "::warning::The PMG cloud sync failed. The error above says which cloud policy applies."
  fi
fi
