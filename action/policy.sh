#!/bin/sh
# Fetches the cloud policy before the first install of the job, so that
# install applies it. The step fails when no cloud policy applies. The
# arguments are the command that runs pmg: `pmg`, or the sudo prefix and
# the binary of the root daemon, so the fetch fills the cache that the
# daemon reads. The fetch takes 15 seconds at most: 5 seconds for the sync
# lock and 10 seconds for the fetch. A PMG release without --require-policy
# runs the full sync, and a failure only warns. POSIX sh, because server
# mode runs in job containers that have no bash.
set -eu
if [ "${PMG_CLOUD_ENABLED:-}" != "true" ]; then
  exit 0
fi

if "$@" cloud sync --help 2>/dev/null | grep -q -- '--require-policy'; then
  "$@" cloud sync --require-policy
elif ! "$@" cloud sync --timeout 10s; then
  printf '%s\n' "::warning::The PMG cloud sync failed. See the error above."
fi
