#!/usr/bin/env bash
# Runs the post step of the action by hand, as the runner runs it, so a job
# can check its exit status and its job summary. The post step at the end of
# the job then finds no proxy and passes. Usage:
#   action-post.sh <expected exit status> [NAME=value ...]
# The pairs set the STATE_* values and the INPUT_* inputs of the post step.
set -uo pipefail
want="$1"
shift
summary="${RUNNER_TEMP}/pmg-post-summary.md"
: > "$summary"
# The post step prints workflow commands. A test run must not turn them into
# annotations on the pull request.
token="pmg-post-$$-${RANDOM}"
echo "::stop-commands::${token}"
env GITHUB_STEP_SUMMARY="$summary" STATE_run="${PMG_PROXY_RUN:-}" \
  INPUT_FAIL-ON-VIOLATION=true INPUT_AUTO-STOP=true INPUT_BASELINE=true \
  "$@" node "${GITHUB_WORKSPACE}/action/post.js"
got=$?
cat "$summary"
echo "::${token}::"
if [ "$got" -ne "$want" ]; then
  echo "::error::The post step exited ${got}, want ${want}." >&2
  exit 1
fi
