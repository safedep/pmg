#!/usr/bin/env python3
"""Joins the POC scenario results with PMG and Tetragon events.

Reads, from the results directory:
  results.jsonl     one line per scenario (scenarios.sh)
  pmg-events.jsonl  the PMG event log (collect.sh)
  tetragon.jsonl    the Tetragon export file (collect.sh)
  timings.json      start-up times (workflow)

Writes report.md and prints it. Exits 1 when a scenario does not match the
expectation for the mode and POC_STRICT=1.
"""

import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

MODE = os.environ.get("POC_MODE", "unprotected")
RESULTS = Path(os.environ.get("POC_RESULTS", "results"))
STRICT = os.environ.get("POC_STRICT") == "1"

SCENARIOS = {
    "T1": "Install a known malicious npm package",
    "T2": "Install a known malicious PyPI package",
    "T3": "Install an npm version younger than the cooldown",
    "T4": "Install script steals `.npmrc` and sends data out over HTTPS and port 8080",
    "T5": "Read the memory of `Runner.Worker`, where secrets live",
    "T6": "Open a reverse shell with `bash /dev/tcp`",
    "T7": "Download the malicious tarball with `env -i curl`",
    "T8": "Stop and resume the PMG daemon",
}


def read_jsonl(path):
    out = []
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def parse_time(value):
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        return dt.datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def kv(detail):
    return dict(part.split("=", 1) for part in detail.split() if "=" in part)


results = {r["id"]: r for r in read_jsonl(RESULTS / "results.jsonl")}
pmg_events = read_jsonl(RESULTS / "pmg-events.jsonl")
tg_events = read_jsonl(RESULTS / "tetragon.jsonl")
timings = {}
if (RESULTS / "timings.json").exists():
    timings = json.loads((RESULTS / "timings.json").read_text())

for e in pmg_events:
    e["_t"] = parse_time(e.get("timestamp"))

# Tetragon process index: exec_id -> process, from every event that carries one.
procs = {}
kprobes = []
for e in tg_events:
    for kind in ("process_exec", "process_exit", "process_kprobe"):
        body = e.get(kind)
        if not body:
            continue
        for key in ("process", "parent"):
            p = body.get(key)
            if p and p.get("exec_id"):
                procs.setdefault(p["exec_id"], p)
        if kind == "process_kprobe":
            body["_t"] = parse_time(e.get("time"))
            kprobes.append(body)


def short(p):
    binary = os.path.basename(p.get("binary", "?"))
    args = (p.get("arguments") or "").split()
    tail = " ".join(args[:2])
    if len(tail) > 40:
        tail = tail[:37] + "..."
    return f"{binary} {tail}".strip()


def chain(p, depth=6):
    names = []
    seen = set()
    while p and depth > 0 and p.get("exec_id") not in seen:
        seen.add(p.get("exec_id"))
        names.append(short(p))
        p = procs.get(p.get("parent_exec_id", ""))
        depth -= 1
    return " ← ".join(names)


def proc_by_pid(pid, at):
    best = None
    for p in procs.values():
        if p.get("pid") != pid:
            continue
        start = parse_time(p.get("start_time")) or 0
        if at is None or start <= at + 1:
            if best is None or start > (parse_time(best.get("start_time")) or 0):
                best = p
    return best


def window(items, r, slack_before=1.0, slack_after=4.0):
    lo, hi = r["start"] - slack_before, r["end"] + slack_after
    return [i for i in items if i.get("_t") and lo <= i["_t"] <= hi]


def pmg_in(r, types):
    return [e for e in window(pmg_events, r) if e.get("event_type") in types]


def tg_in(r, policy):
    return [k for k in window(kprobes, r) if k.get("policy_name") == policy]


def killed(events):
    return any("SIGKILL" in str(k.get("action", "")) for k in events)


def sock(k):
    for a in k.get("args", []):
        if "sock_arg" in a:
            s = a["sock_arg"]
            return f"{s.get('daddr')}:{s.get('dport')}"
    return ""


def file_path(k):
    for a in k.get("args", []):
        if "file_arg" in a:
            return a["file_arg"].get("path", "")
    return ""


def int_args(k):
    return [a["int_arg"] for a in k.get("args", []) if "int_arg" in a]


def describe_tg(events):
    if not events:
        return "nothing"
    k = events[0]
    what = sock(k) or file_path(k) or ",".join(str(i) for i in int_args(k))
    action = "killed" if killed(events) else "reported"
    return f"{k.get('policy_name')}: {k.get('function_name')} {what} ({action})"


def describe_pmg(events):
    if not events:
        return "nothing"
    e = events[0]
    d = e.get("details") or {}
    if e.get("event_type") == "network_policy":
        return f"network_policy {d.get('action', '')} {d.get('hostname', '')} ({d.get('mode', '')})"
    pkg = f"{e.get('package_name', '')}@{e.get('version', '')}".strip("@")
    return f"{e.get('event_type')} {pkg}"


def client_chain(r, host_hint=None):
    """Process chain for the client PMG saw in this window, through Tetragon."""
    for e in window(pmg_events, r):
        d = e.get("details") or {}
        pid = d.get("client_pid")
        if not pid:
            continue
        if host_hint and host_hint not in str(d.get("hostname", "")):
            continue
        p = proc_by_pid(int(pid), e["_t"])
        if p:
            return chain(p)
        return f"{d.get('client_comm', '')} (pid {pid})"
    return ""


def tg_chain(events):
    for k in events:
        if k.get("process"):
            return chain(k["process"])
    return ""


protected = MODE != "unprotected"


def judge(tid, r):
    """Returns (ok, result text, pmg text, tetragon text, chain)."""
    d = kv(r.get("detail", ""))
    rc = r["rc"]
    if rc == -1:
        return None, f"skipped: {r.get('detail')}", "", "", ""

    if tid in ("T1", "T2", "T7"):
        eco_hint = "pypi" if tid == "T2" else "npm"
        blocked = pmg_in(r, {"malware_blocked", "malware_confirmed"})
        if tid == "T7":
            got = d.get("http_code", "")
            res = f"HTTP {got}, rc {rc}"
            stopped = got != "200"
        else:
            stopped = d.get("installed") == "no"
            res = f"installed: {d.get('installed')}, rc {rc}"
        ok = (stopped and bool(blocked)) if protected else not stopped
        host = "pythonhosted" if eco_hint == "pypi" else "npmjs"
        return ok, res, describe_pmg(blocked), "", client_chain(r, host)

    if tid == "T3":
        held = pmg_in(r, {"dependency_cooldown"})
        res = f"rc {rc} ({d.get('package', '')})"
        # npm sees the version stripped from metadata, so PMG may record no
        # download event. A failed install with PMG in the path is the result.
        ok = (rc != 0) if protected else (rc == 0)
        return ok, res, describe_pmg(held) if held else ("version hidden from metadata" if protected and rc != 0 else "nothing"), "", client_chain(r, "npmjs")

    if tid == "T4":
        code = d.get("https_code", "")
        port_rc = d.get("port8080_rc", "")
        net = pmg_in(r, {"network_policy"})
        egress = tg_in(r, "ci-egress")
        res = f"HTTPS exfil: {code}; port 8080 curl rc {port_rc}"
        if MODE == "unprotected":
            ok = code == "200" and port_rc != "137"
        elif MODE == "audit":
            ok = code == "200" and bool(net) and bool(egress)
        else:
            ok = code != "200" and bool(net) and port_rc == "137" and killed(egress)
        return ok, res, describe_pmg(net), describe_tg(egress), tg_chain(egress) or client_chain(r, "example.com")

    if tid == "T5":
        ev = [k for k in tg_in(r, "runner-secrets") if file_path(k).endswith("/mem")]
        res = f"rc {rc}"
        if MODE == "unprotected":
            ok = rc == 0
        elif MODE == "audit":
            ok = rc == 0 and bool(ev)
        else:
            ok = rc != 0 and killed(ev)
        return ok, res, "", describe_tg(ev), tg_chain(ev)

    if tid == "T6":
        ev = tg_in(r, "reverse-shell")
        res = f"rc {rc}"
        if MODE == "unprotected":
            ok = rc == 124
        elif MODE == "audit":
            ok = rc == 124 and bool(ev)
        else:
            ok = rc == 137 and killed(ev)
        return ok, res, "", describe_tg(ev), tg_chain(ev)

    if tid == "T8":
        pid = d.get("pmg_pid")
        ev = [k for k in tg_in(r, "pmg-tamper")
              if k.get("function_name", "").endswith("kill") and pid and str(pid) in [str(i) for i in int_args(k)]]
        res = f"SIGSTOP and SIGCONT sent to pmg (pid {pid})"
        ok = bool(ev)
        return ok, res, "", describe_tg(ev), tg_chain(ev)

    return None, "unknown scenario", "", "", ""


rows = []
failures = []
for tid, title in SCENARIOS.items():
    r = results.get(tid)
    if not r:
        rows.append((tid, title, "not run", "", "", "", "—"))
        continue
    ok, res, pmg_txt, tg_txt, ch = judge(tid, r)
    mark = "—" if ok is None else ("✅" if ok else "❌")
    if ok is False:
        failures.append(tid)
    rows.append((tid, title, res, pmg_txt, tg_txt, ch, mark))


def esc(s):
    return str(s).replace("|", "\\|")


out = []
out.append(f"## PMG + Tetragon POC: `{MODE}`\n")
expect = {
    "unprotected": "No PMG, no Tetragon. Every attack is expected to succeed.",
    "audit": "PMG blocks packages and reports network policy matches. Tetragon reports.",
    "enforce": "PMG blocks packages and denies off-profile hosts. Tetragon kills on high-confidence detections.",
}[MODE]
out.append(expect + "\n")
out.append("| Test | Scenario | Result | PMG saw | Tetragon saw | Process chain | Matches expectation |")
out.append("| --- | --- | --- | --- | --- | --- | --- |")
for row in rows:
    out.append("| " + " | ".join(esc(c) for c in row) + " |")
out.append("")

if timings:
    out.append("**Start-up cost:** " + ", ".join(f"{k} {v} s" for k, v in timings.items()) + "\n")

if pmg_events or tg_events:
    counts = {}
    for e in pmg_events:
        counts[f"PMG {e.get('event_type')}"] = counts.get(f"PMG {e.get('event_type')}", 0) + 1
    for k in kprobes:
        key = f"Tetragon {k.get('policy_name')}"
        counts[key] = counts.get(key, 0) + 1
    execs = sum(1 for e in tg_events if "process_exec" in e)
    counts["Tetragon process_exec"] = execs
    out.append("**Events in this job:** " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) + "\n")

    bpf_loaders = sorted({os.path.basename(k["process"].get("binary", ""))
                          for k in kprobes
                          if k.get("function_name") == "bpf_check" and k.get("process")})
    if bpf_loaders:
        out.append("**BPF program loads by:** " + ", ".join(bpf_loaders) + "\n")

out.append(f"**Result:** {len(failures)} of {sum(1 for r in rows if r[-1] != '—')} checked scenarios did not match"
           + (f" ({', '.join(failures)})" if failures else "") + ".\n")

text = "\n".join(out)
(RESULTS / "report.md").write_text(text)
print(text)
sys.exit(1 if failures and STRICT else 0)
