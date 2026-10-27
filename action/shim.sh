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
