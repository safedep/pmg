#!/bin/bash
# Throwaway test helper for the ARC validation runbook. Runs one case and
# prints one verdict line. Usage: case.sh <id> <command...>
id=$1; shift
logs=${PMG_LOG_GLOB:-/root/.config/safedep/pmg/logs/*-pmg.log}
cnt() { { sudo -n sh -c "cat $logs" 2>/dev/null || sh -c "cat $logs" 2>/dev/null; } | grep -c '"event_type":"malware_blocked"'; }
before=$(cnt); out=$("$@" 2>&1); rc=$?; after=$(cnt)
if grep -qE 'E403|^403$' <<<"$out"; then v=BLOCKED
elif grep -qE 'added [0-9]+ package|Successfully built|^200$' <<<"$out"; then v=INSTALLED
elif grep -qiE 'SELF_SIGNED|UNABLE_TO|certificate' <<<"$out"; then v=TLS-ERROR
else v=OTHER; fi
line="$id $v rc=$rc pmg_blocks=+$((after - before)) at $(date -u +%H:%M:%S)"
echo "$line"
if [ -n "${RESULTS:-}" ]; then echo "$line" >> "$RESULTS"; fi
grep -E 'GET|E403|added|error|ERR' <<<"$out" | head -8
