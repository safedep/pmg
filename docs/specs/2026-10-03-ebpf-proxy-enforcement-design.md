# eBPF enforcement for the persistent proxy on Linux

Status: proposal. POC verified on 2026-10-03. See
[scripts/ebpf-enforce-poc](../../scripts/ebpf-enforce-poc/README.md).

## Problem

The persistent proxy ([persistent-proxy.md](../persistent-proxy.md)) routes
traffic with environment variables. A process decides whether it honors them.
The POC showed three common cases that bypass the proxy today:

- Node ignores `HTTP_PROXY` unless `NODE_USE_ENV_PROXY=1` is set. A script
  that calls `fetch()` goes direct.
- `env -i`, `sudo`, and tools that scrub the environment drop the variables.
- `curl` with HTTP/3 probes UDP port 443 first. A QUIC client never touches an
  HTTP proxy.

The threat that matters most is a package install script. It runs with its
own HTTP client and downloads a second stage. The proxy never sees it.

## Goal

When a user opts in, the Linux kernel routes every TCP connection to the
configured ports (80 and 443 by default) from every eligible process to the
PMG proxy. A process cannot opt out. The proxy handles the connection with the
same interceptors it uses today.

Eligibility is a policy. The default is eligible. The CI runner agent, the
proxy daemon, and `pmg` itself are exempt.

## Non-goals

- Containment of a hostile process. A process with the same uid can borrow an
  exemption with `ptrace` where Yama allows it. The sandbox owns that threat.
- Traffic from containers that a job starts. They live in another cgroup and
  have their own loopback.
- DNS. Only TCP to the configured ports is routed.
- macOS and Windows.

## Mechanism choice

| Mechanism | Rewrites destination | Per-process eligibility | Original destination | Verdict |
| --- | --- | --- | --- | --- |
| cgroup BPF `connect4/6` + `sockops` | yes | pid, uid, executable inode, cgroup | socket storage + map | chosen |
| netfilter `nat REDIRECT` with `-m owner` or `-m cgroup` | yes | uid, gid, cgroup path only | `SO_ORIGINAL_DST` | rejected |
| BPF LSM `socket_connect` | no, deny only | full task context | n/a | complement for strict mode |
| network namespace with one route to the proxy | n/a | by placement | n/a | rejected |
| `LD_PRELOAD` | yes | n/a | n/a | rejected, cooperative |

netfilter fails on the one requirement that matters. On a GitHub Actions
runner, `Runner.Listener`, `Runner.Worker` and every job step run as the same
user in the same cgroup. Only a hook that sees the calling task can separate
them. The cgroup `connect4` hook does, and it can also rewrite the address.

## POC results

Host: kernel 6.18, cgroup v2 (hybrid mount), root, `kernel.unprivileged_bpf_disabled=2`.
Loader: `cilium/ebpf` v0.22, no cgo, CO-RE object built with clang 18.

| Check | Result |
| --- | --- |
| `connect4` rewrites TCP 80/443 to the local listener for `curl`, `python3` and `node` started with `env -i` | pass |
| Original destination recovered after `accept()` from a map keyed by the client source port | pass, exact IP and port |
| Exemption by executable `(dev, inode)` evaluated in the kernel with `bpf_get_current_task_btf` | pass, verifier accepts it in `cgroup/connect4` |
| Exempt `curl` copy reaches the real registry | pass, HTTP 200 from registry.npmjs.org |
| Client that does not trust the CA | fails closed with a certificate error |
| Attach to a sub-cgroup only | pass, a process outside the cgroup goes direct |
| UDP 80/443 denied for eligible processes (`connect4` + `sendmsg4`) | pass, `curl` probed QUIC 12 times and then fell back to TCP |
| Unprivileged process opens the pinned map read-only under `unprivileged_bpf_disabled=2` | pass |
| `cgroup/sockops` loads with libbpf section name `sockops` | pass |

The POC does not cover IPv6 (`connect6`), `getpeername` rewrite, and a
`BPF_MAP_TYPE_LRU_HASH` for the original destination map. The design below
includes them.

## Design

Three parts. Each part has one owner and a narrow seam.

### 1. `internal/netenforce` (new, Linux only)

The kernel side and its supervisor. Nothing in `proxy/` imports it.

- `Policy`: `Ports []uint16`, `ExemptExecutables []string`, `ExemptPIDs []int`,
  `ExemptUIDs []int`, `CgroupPath string`, `DenyUDP bool`. Pure Go. Unit tests.
- `Target`: the proxy address to redirect to. The command layer reads it from
  the proxy state file and passes it in.
- `Attach(ctx, Target, Policy) (*Handle, error)`: loads the CO-RE object,
  fills the maps, attaches `connect4`, `connect6`, `sendmsg4`, `sendmsg6` and
  `sockops` to `CgroupPath` with `bpf_link` (multi-attach, so it coexists with
  systemd or Cilium programs). Pins the original destination map at
  `<bpffs>/pmg/<state-id>/orig_dst` with mode `0644`.
- `Handle.Detach()`: closes the links and removes the pin.
- `OriginalDestinations`: opens the pinned map read-only and resolves
  `Lookup(clientPort uint16) (netip.AddrPort, bool)`. This is the only type the
  proxy consumes, through an interface the proxy defines.
- `Probe()`: kernel version, BTF present, cgroup v2 mounted, bpffs mounted,
  capabilities. Mirrors the sandbox probes. `pmg proxy enforce --check` and
  `pmg doctor` call it.
- `bpf/`: the C source, the `bpf2go` output, and the committed `.o`. CI
  rebuilds the object and fails on a diff. The object declares
  `Dual BSD/GPL`. The kernel requires a GPL-compatible licence for
  `bpf_get_current_task_btf`. The Go code stays Apache-2.0. Cilium uses the
  same split.

In-kernel decision per `connect()`, in order:

1. Destination is loopback. Pass.
2. Destination port is not in `Ports`. Pass.
3. `tgid` is in `exempt_tgid`. Pass.
4. `uid` is in `exempt_uid`. Pass.
5. Executable `(dev, inode)` is in `exempt_exe`. Pass.
6. Store the original destination in socket storage. Rewrite the destination
   to `Target`. The `sockops` hook copies the stored value into
   `orig_dst_by_sport` when the kernel assigns the source port.

UDP to a port in `Ports` from an eligible process returns `EPERM`. A QUIC
client falls back to TCP. IPv6 follows the same rules. When the proxy has no
IPv6 listener, `connect6` denies instead of redirecting.

Executable inode is the primary exemption. It is race-free for processes that
start later, such as a new `Runner.Worker` on a persistent self-hosted runner.
Pid exemption covers exact long-lived processes. Uid exemption covers setups
where the agent runs as a different user than the job.

Default exemptions, computed by the command:

- The proxy daemon pid from the state file.
- The `pmg` executable. `pmg proxy stop` and `pmg cloud sync` dial SafeDep
  Cloud directly. `pmg npm install` starts an ephemeral proxy that must not
  be routed into the persistent one.
- Every ancestor pid of the `enforce` command. On GitHub Actions this is
  `bash`, `Runner.Worker`, `Runner.Listener` and their parents.
- The executables of ancestors whose basename matches a known CI agent
  (`Runner.Listener`, `Runner.Worker`, `Runner.PluginHost`, `gitlab-runner`,
  `buildkite-agent`). The pid rule alone misses a `Runner.Worker` that starts
  for the next job.

The command exempts generic ancestors like `bash` and `sudo` by pid only.
Exempting their inode would exempt every shell on the host.

### 2. `proxy`: transparent listener

A redirected client does not speak the proxy protocol. It sends a TLS
`ClientHello` or an origin-form HTTP request. `TransparentListener` wraps the
existing `net.Listener` and sniffs the first bytes of each connection:

- `CONNECT` or an absolute-URI request: pass through unchanged. The existing
  goproxy path handles it.
- `0x16`: TLS. Peek the `ClientHello` without consuming it and read the SNI.
  Ask the interceptors with the existing `ShouldIntercept` and `ShouldMITM`
  for `host:443`. When one says yes, wrap the connection in `tls.Server` with
  the certificate manager and hand it to the `http.Server`. The request then
  lands in goproxy's `NonproxyHandler`, which sets `URL.Scheme` from
  `req.TLS` and `URL.Host` from `Host`, and calls `proxy.ServeHTTP`. The
  interceptors, block rendering and upstream retries run unchanged. When no
  interceptor wants the host, dial the original destination and splice bytes.
  This is what `goproxy.OkConnect` does for CONNECT today.
- Anything else: plain HTTP. `NonproxyHandler` builds the absolute URL from
  `Host` and calls `proxy.ServeHTTP`.

The original destination comes from a `proxy.OriginalDestinationResolver`
interface with one method. `netenforce` implements it. When the resolver has
no entry (kernel older than 5.19 cannot give an unprivileged daemon the map),
the listener falls back to SNI or `Host` plus the sniffed protocol. A TLS
connection without SNI and without a map entry is closed and logged.

One listener, not a second port. The redirect target is the address already
in the state file, and the sniff is unambiguous. `pmg proxy start` gains no
flag. The daemon opens the pinned map lazily on the first redirected
connection, so `enforce` needs no daemon restart.

Non-registry hosts are spliced, not MITM'd. This matters: enforcement adds no
new trust requirement for `github.com`, Azure blob storage, or `apt`. Only
registry hosts need the PMG CA, which is the same requirement as today. A
client that ignores the proxy environment and does not trust the CA fails
closed on registry hosts only.

### 3. Command and action

`pmg proxy enforce` (Linux). It needs `CAP_BPF`, `CAP_NET_ADMIN` and
`CAP_PERFMON`, so it runs under `sudo`. Flags: `--state`, `--exempt-exe`,
`--exempt-pid`, `--exempt-uid`, `--port`, `--cgroup`, `--check`, `--off`.
Ports default to 80, 443 plus every port in `proxy.registries`.

The command is a supervisor. It attaches, writes `enforce-state.json` next to
the proxy state file, and stays resident as a small root process that holds
the links. It detaches when the proxy daemon pid exits (`pidfd_open` and
poll), on `pmg proxy enforce --off`, or on `SIGTERM`. The alternative, pinned
links that outlive the daemon, redirects every eligible connection to a dead
port after `pmg proxy stop` and breaks post-job steps such as
`actions/upload-artifact`. A crashed daemon already fails the job through
`pmg proxy stop --fail-on-violation`, so auto-detach does not weaken the gate.

`pmg proxy status` reports the enforcement state. `pmg proxy stop` prints a
warning when `enforce-state.json` exists and the supervisor is gone.

The default cgroup is the one that contains the `enforce` command. On a
GitHub Actions runner that is the runner's own cgroup, so system daemons are
out of scope and containers started by the job are not redirected into a
loopback they cannot reach. `--cgroup /sys/fs/cgroup` widens it on purpose.

`action.yml` gains `enforce: "true"`, valid with `server-mode`. The action
passes one explicit `--state` path to `start`, `enforce` and `stop`, because
`sudo` changes `HOME` and with it the default cache directory. Without `sudo`
the action fails with a clear error.

## Requirements

- Linux 5.15 or later with `CONFIG_DEBUG_INFO_BTF`, `CONFIG_CGROUP_BPF`,
  cgroup v2 and bpffs mounted. Verified on 6.18. GitHub hosted runners meet
  this.
- Linux 5.19 or later for the unprivileged daemon to read the pinned map.
  Older kernels degrade to SNI-only resolution.
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` for the supervisor.

## Limitations

- Same-uid evasion. See non-goals.
- Processes in other cgroups, including containers, are not covered unless
  the user attaches at the root cgroup and accepts that containers break.
- A TLS client with Encrypted ClientHello hides the SNI. The listener splices
  it to the original destination and logs it. It cannot inspect it.
- A client that pins certificates fails closed on registry hosts. Same as today.
- Cost: one hash lookup per `connect()` and one `sockops` callback. Not
  measurable against a TCP handshake.

## Rollout

1. Transparent listener in `proxy/`, with `test/proxye2e` cases: raw TLS with
   SNI to a registry host, origin-form HTTP, a non-registry host spliced. No
   BPF. About 400 lines.
2. `internal/netenforce`, `pmg proxy enforce`, and an e2e test behind
   `//go:build linux && ebpf_e2e` that runs under `sudo` on `ubuntu-latest` in
   `persistent-proxy-e2e.yml`. About 900 lines of Go and 200 of C.
3. `action.yml` input, `persistent-proxy.md` update, and an acceptance script
   with a `catalog.yaml` row.

## Decisions needed

1. Supervisor process with auto-detach (recommended) or pinned links until an
   explicit `--off`.
2. Default cgroup: the one that contains `pmg` (recommended) or the root.
3. Commit the compiled object with a CI reproducibility check (recommended)
   or build it at release time.
4. Strict mode later: deny all other outbound TCP from eligible processes.
