#!/bin/sh
# Fetches the cloud policy before the first install of the job, so that
# install applies it. The step fails when no cloud policy applies.
#
# The arguments are the command that runs pmg. Shim mode and server mode
# pass `pmg`. Enforce mode passes the sudo prefix and the binary of the root
# daemon, so the fetch fills the cache that the daemon reads.
#
# The fetch waits at most 5 seconds for the sync lock and runs for at most
# 20 seconds. A PMG release without --require-policy runs the full sync, and
# a failure only warns. When pmg cannot run, the step fails. POSIX sh,
# because server mode runs in job containers that have no bash.
set -eu
if [ "${PMG_CLOUD_ENABLED:-}" != "true" ]; then
  exit 0
fi

help="$("$@" cloud sync --help)"
case "$help" in
  *--require-policy*)
    "$@" cloud sync --require-policy --timeout 20s
    ;;
  *)
    if ! "$@" cloud sync --timeout 10s; then
      printf '%s\n' "::warning::The PMG cloud sync failed. See the error above."
    fi
    ;;
esac
