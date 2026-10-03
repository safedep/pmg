# eBPF enforcement for the persistent proxy on Linux

Status: proposal, revision 3. POC verified on 2026-10-03. See
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

Eligibility is a policy. The default is eligible. The CI runner agent and the
proxy itself are exempt.

## Non-goals

- Containment of a hostile process. A process with the same uid can borrow an
  exemption with `ptrace` where Yama allows it. The sandbox owns that threat.
- Traffic from containers. They have their own network namespace and their
  own loopback. See "Scope".
- DNS. Only TCP to the configured ports is routed.
- Routing on macOS and Windows. The interface exists there and reports that
  enforcement is not supported.

## Enforcement is a feature of the proxy server

From the user's view, enforcement makes a proxy server deployment reliable.
It is not a separate product. The user turns it on where they start the
server, with `pmg proxy start --enforce` or with `proxy.server.enforce` in the
config file. The same state file describes the server and its enforcement.
`pmg proxy status` and `pmg proxy stop` see both.

In code, enforcement stays isolated. `internal/netenforce` knows nothing about
goproxy or interceptors. `proxy/` knows nothing about BPF. `internal/proxyserver`
wires the two together, the same way it wires the analyzer and the
certificate manager today.

Enforcement runs inside the daemon process, as a goroutine. The BPF programs
are attached through file descriptors the daemon holds. When the daemon
exits, for any reason, the kernel detaches them. There is no second process,
no second state file, and nothing to clean up after a crash. A crashed daemon
already fails the job through `pmg proxy stop --fail-on-violation`, so this
does not weaken the gate.

### Root

Attaching cgroup BPF programs needs `CAP_BPF`, `CAP_NET_ADMIN` and
`CAP_PERFMON`. With `--enforce` the daemon runs as root. Without the
capabilities it refuses to start with a clear error. The consequences:

- The daemon parses TLS and HTTP from the internet and from packages. A bug
  there is now a root bug. On a GitHub hosted runner this changes little: the
  runner user already has passwordless `sudo`. On a persistent self-hosted
  runner it is a real step up. The hardening follow-up is to attach as root
  and then hand the link and map file descriptors to a child that runs as the
  invoking user. `Daemonize` already re-executes the binary, so the seam
  exists. This is not in the first version.
- The state file, the event log and the cache are owned by root. In enforce
  mode every `pmg proxy` lifecycle command runs under `sudo`. The GitHub
  Action passes one explicit `--state` path, because `sudo` resets `HOME`.
- Cloud credentials come from the environment, not from a keychain. The
  action already does this.

- The CA keypair moves. `pmg setup cert install` refuses to run under `sudo`
  today, because it keeps the keypair in the user's config directory for an
  unprivileged proxy. A root daemon reads root's config directory. In enforce
  mode the daemon reads the keypair from `/etc/safedep/pmg/` (key mode
  `0600`, owned by root), and `pmg setup cert install --system` writes it
  there when it runs as root. The user scope flow does not change.

### Trust delivery

eBPF cannot set a process's environment. The hooks see syscalls, and the
environment is userspace memory that `exec()` fixes. Enforcement removes the
proxy variables (`HTTP_PROXY` and the others). It does not deliver trust.

Enforce mode uses one mechanism for trust: the system trust store, through
the existing `pmg setup cert install --system`. `pmg proxy start --enforce`
refuses to start when the CA is not in the store. It does not emit the
per-tool trust variables.

Trust only decides whether a legitimate tool works. It never decides whether
a connection bypasses the proxy. The kernel routes every eligible connection
to the proxy first. A client that does not trust the CA fails the handshake
on a registry host and gets nothing. So a gap in trust delivery breaks a
tool. It does not open a hole.

Measured on 2026-10-03 with the POC, the CA in `/usr/local/share/ca-certificates`,
and every client started with `env -i`:

| Client | Trusts the system store |
| --- | --- |
| `curl`, Python `urllib`, Go `net/http` | yes |
| pip 26.2 upstream, pip 24.0 Debian | yes |
| npm 10.9 on Node 22.22 | no |
| npm and `fetch()` with `--use-system-ca` | yes |
| Python `requests` (`certifi` bundle) | no |

Node is the one gap that matters, because it holds npm, pnpm, yarn and aube.
Node 22.15 and later read the system store when `NODE_USE_SYSTEM_CA=1` is
set. Enforce mode keeps that one variable. The action writes it to
`$GITHUB_ENV`, and a systemd deployment writes it to the runner's `.env`.
When a process drops it, Node fails closed. Node 20 has no switch, and it
reached end of life in April 2026. Enforce mode does not support it.

A script that uses `requests` directly fails closed on registry hosts. That
is the wanted result for an install script. pip does not use the `certifi`
bundle for its own downloads, so pip works.

Not measured yet: `uv`, `poetry`, `pipx`, `bun`. `uv` validates against its
own bundled roots unless `UV_NATIVE_TLS` is set, so it probably needs a
second variable. Phase 3 measures each supported package manager in the
acceptance suite and adds a variable only where a measurement shows the
need.

## Mechanism choice

| Mechanism | Rewrites destination | Per-process eligibility | Original destination | Verdict |
| --- | --- | --- | --- | --- |
| cgroup BPF `connect4/6` + `sockops` | yes | pid, uid, executable, netns | socket storage + map | chosen |
| netfilter `nat REDIRECT` with `-m owner` or `-m cgroup` | yes | uid, gid, cgroup path only | `SO_ORIGINAL_DST` | rejected |
| BPF LSM `socket_connect` | no, deny only | full task context | n/a | not available, see below |
| network namespace with one route to the proxy | n/a | by placement | n/a | rejected |
| `LD_PRELOAD` | yes | n/a | n/a | rejected, cooperative |

netfilter fails on the one requirement that matters. On a GitHub Actions
runner, `Runner.Listener`, `Runner.Worker` and every job step run as the same
user in the same cgroup. Only a hook that sees the calling task can separate
them. The cgroup `connect4` hook does, and it can also rewrite the address.

BPF LSM needs `bpf` in the kernel's active LSM list. Ubuntu does not ship it
there. Turning it on needs a boot parameter and a reboot, which a hosted
runner cannot do. The design does not depend on it.

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
| Only sockets in the proxy's network namespace are redirected (`bpf_get_netns_cookie`) | pass, a `curl` under `unshare -n` is left alone |
| UDP 80/443 denied for eligible processes (`connect4` + `sendmsg4`) | pass, `curl` probed QUIC 12 times and then fell back to TCP |
| Unprivileged process opens a pinned map read-only | pass, not needed by the final design |
| `cgroup/sockops` loads with libbpf section name `sockops` | pass |

The POC does not cover IPv6 (`connect6`), the exec tracepoint, and a
`BPF_MAP_TYPE_LRU_HASH` for the original destination map. All three are
standard and the design includes them.

## Design

### 1. `internal/netenforce`: the contract

The package defines the contract on every platform and implements it on Linux.

```go
type Policy struct {
	Ports             []uint16 // default 80, 443, plus proxy.registries ports
	EligibleUsers     []string // empty means every user is eligible
	ExemptUsers       []string
	ExemptExecutables []string // paths or globs, re-resolved on every exec
	CgroupPath        string   // default: the cgroup v2 root
	DenyUDP           bool     // default true
}

type Target struct {
	Addr netip.AddrPort // the proxy listener
}

type Enforcer interface {
	Attach(ctx context.Context, t Target, p Policy) (Handle, error)
	Probe() ProbeResult
}

type Handle interface {
	OriginalDestination(clientPort uint16) (netip.AddrPort, bool)
	Status() Status
	Close() error
}

func New() (Enforcer, error) // ErrUnsupported on every platform but Linux
```

`proxy/` consumes `OriginalDestination` through its own one-method interface.
`internal/proxyserver` passes the `Handle` in. Nothing else crosses the seam.

On macOS and Windows `New()` returns `ErrUnsupported`. `pmg proxy start
--enforce` turns that into a `usefulerror` with the platform in the message.
The build has no BPF code on those platforms. The Linux implementation sits
behind `//go:build linux`, like `sandbox/platform`.

### 2. Eligibility

Users describe eligibility in terms they can know in advance: ports, users
and executable paths. There is no pid in the policy. A user cannot know a pid
when they write a config file or a systemd unit. Pids are an implementation
detail the kernel programs use.

The kernel decides per `connect()`, in this order:

1. The socket is in another network namespace than the proxy. Pass.
2. Destination is loopback. Pass.
3. Destination port is not in `Ports`. Pass.
4. `tgid` is in `exempt_tgid`. Pass.
5. `uid` is in `exempt_uid`, or `eligible_uid` is non-empty and does not hold
   the uid. Pass.
6. Executable `(dev, inode)` is in `exempt_exe`. Pass.
7. Store the original destination. Rewrite the destination to the proxy.

UDP to a port in `Ports` from an eligible process returns `EPERM`. A QUIC
client falls back to TCP. IPv6 follows the same rules. When the proxy has no
IPv6 listener, `connect6` denies instead of redirecting.

The daemon fills the maps:

- `exempt_tgid` holds the daemon's own pid. Without it the proxy's upstream
  connections would loop back into itself.
- `exempt_exe` holds the inode of every path that matches
  `ExemptExecutables`, plus the `pmg` binary. `pmg proxy stop` and
  `pmg cloud sync` dial SafeDep Cloud directly, and `pmg npm install` starts
  an ephemeral proxy that must not be routed into the persistent one.
- A `tp_btf/sched_process_exec` program reports every exec to the daemon
  through a ring buffer. The daemon reads `/proc/<pid>/exe`, matches the
  globs again, and adds the new inode and the pid. `sched_process_exit`
  removes the pid. This is what keeps a self-hosted runner working after it
  updates itself into a new versioned directory, with new binaries and new
  inodes. The inode check in step 6 is race-free. The exec path adds about a
  hundred microseconds of latency and a miss fails closed for that one
  process.

The GitHub Actions profile: when `GITHUB_ACTIONS=true`, the daemon walks its
own ancestors, finds `Runner.Worker`, and adds `<dir>/Runner.*` to the globs.
Users on other CI systems add their agent binary to `ExemptExecutables`.
The `node` processes that run JavaScript actions stay eligible. They reach
`github.com`, Azure blob storage and `nodejs.org`, which are not registry
hosts, so the proxy splices them without MITM and they need no trust change.

### 3. Original destination

After the kernel rewrites the destination, the proxy's accepted socket only
knows that the peer is `127.0.0.1:<ephemeral>`. The proxy needs to know where
the client wanted to go, for three reasons:

- A non-registry host is spliced to its real destination without MITM. SNI
  gives a name, not the address the client resolved. Resolving again can give
  a different answer and loses the port.
- A private registry on a non-standard port. SNI and `Host` do not carry the
  original port when the client used one that is not 443.
- TLS without SNI, or an IP literal. There is nothing else to go on.

The mechanism: `connect4` stores the original address in `bpf_sk_storage`,
which lives and dies with the client socket. The `sockops` hook fires when
the kernel assigns the source port and copies the entry into an LRU hash
keyed by that port. The proxy looks the port up after `accept()` and deletes
the entry.

Cost: one 16-byte entry per redirected connection, bounded by 65536 source
ports, so under 2 MB at the worst case, and the LRU evicts stale entries
from connections that never reached the proxy. CPU: one `sockops` callback
per TCP connection on the host. It returns after one failed storage lookup
for every socket the hook did not redirect. Neither is measurable against a
TCP handshake. When the lookup misses, the listener falls back to SNI or
`Host` plus the sniffed protocol.

### 4. Scope: namespace and cgroup

The daemon attaches to the cgroup v2 root by default and gates on the
network namespace cookie (`bpf_get_netns_cookie`, verified in the POC). It
reads its own cookie with `SO_NETNS_COOKIE` and writes it into the config
map. A socket in any other namespace passes. This covers both ways a proxy
starts:

- A GitHub Actions step starts it. The runner, the job steps and the proxy
  share the host namespace. All are covered. Containers the job starts are
  in their own namespace and are not touched. Redirecting them to
  `127.0.0.1` would send them to their own loopback and break them.
- `systemd` starts it at boot on a self-hosted runner. The proxy lives in
  `/system.slice/pmg-proxy.service`. The runner lives in
  `/system.slice/actions.runner.*.service`. Neither contains the other, so a
  cgroup scoped to the proxy would cover nothing. The root cgroup plus the
  namespace gate covers the runner, and `ExemptExecutables` and
  `EligibleUsers` do the rest. A typical unit sets
  `eligible_users: [runner]` and exempts the runner binaries.

`CgroupPath` narrows the scope on purpose, for a host where the operator
wants the programs on one service only.

Root-cgroup attach also covers host daemons such as the cloud agent. Their
connections to port 80 or 443 go through the proxy, which splices them
unchanged. An operator who does not want this sets `EligibleUsers`.

### 5. `proxy`: transparent listener

A redirected client does not speak the proxy protocol. It sends a TLS
`ClientHello` or an origin-form HTTP request. `TransparentListener` wraps the
existing `net.Listener` and sniffs the first bytes of each connection:

- `CONNECT` or an absolute-URI request: pass through unchanged. The existing
  goproxy path handles it.
- `0x16`: TLS. Peek the `ClientHello` without consuming it and read the SNI.
  Ask the interceptors with the existing `ShouldIntercept` and `ShouldMITM`
  for `host:port`. When one says yes, wrap the connection in `tls.Server`
  with the certificate manager and hand it to the `http.Server`. The request
  then lands in goproxy's `NonproxyHandler`, which sets `URL.Scheme` from
  `req.TLS` and `URL.Host` from `Host`, and calls `proxy.ServeHTTP`. The
  interceptors, block rendering and upstream retries run unchanged. When no
  interceptor wants the host, dial the original destination and splice
  bytes. This is what `goproxy.OkConnect` does for CONNECT today.
- Anything else: plain HTTP. `NonproxyHandler` builds the absolute URL from
  `Host` and calls `proxy.ServeHTTP`.

One listener, not a second port. The redirect target is the address already
in the state file, and the sniff is unambiguous.

Non-registry hosts are spliced, not MITM'd. Enforcement adds no new trust
requirement for `github.com`, Azure blob storage or `apt`. Only registry
hosts need the PMG CA, which is the requirement today. A client that ignores
the proxy environment and does not trust the CA fails closed on registry
hosts only.

### 6. Command, config and state

`pmg proxy start --enforce` on Linux. The flag binds to
`proxy.server.enforce.enabled`, like `--host` and `--port` bind to their
config keys. The rest of the policy lives in config only:

```yaml
proxy:
  server:
    listen_port: 7777
    enforce:
      enabled: true
      ports: [80, 443]
      eligible_users: [runner]
      exempt_users: []
      exempt_executables:
        - /home/runner/actions-runner/bin/Runner.*
      cgroup: ""
      deny_udp: true
```

`State` gains an `Enforce` block: cgroup, ports, namespace cookie, the
resolved exemptions, and the kernel and loader versions. `pmg proxy status`
prints it. `pmg proxy stop` is unchanged. The daemon exits, the kernel
detaches.

`action.yml` gains `enforce: "true"`, valid with `server-mode`. The action
runs `pmg setup cert install --system`, then `start` and `stop` under `sudo` with one explicit `--state` path
and passes the cloud variables through `--preserve-env`. Without `sudo` the
action fails with a clear error.

A systemd unit for a self-hosted runner runs `pmg proxy start --enforce`
in the foreground as root with a fixed `listen_port`. The operator runs
`pmg setup cert install --system` once. The runner's `.env` file carries
`NODE_USE_SYSTEM_CA=1`. The CA is persisted, so it is stable across
restarts.

## Requirements

- Linux 5.15 or later with `CONFIG_DEBUG_INFO_BTF`, `CONFIG_CGROUP_BPF`,
  cgroup v2 mounted. `SO_NETNS_COOKIE` needs 5.14. Verified on 6.18. GitHub
  hosted runners meet this.
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, so root in practice.
- `Probe()` checks all of it and `pmg doctor` reports it.

## Limitations

- Same-uid evasion. See non-goals.
- Processes in other network namespaces, including containers, are not
  covered. A later version can redirect them to the bridge address instead
  of loopback.
- A TLS client with Encrypted ClientHello hides the SNI. The listener splices
  it to the original destination and logs it. It cannot inspect it.
- A client that pins certificates fails closed on registry hosts. Same as today.
- The daemon runs as root until the privilege-drop follow-up lands.

## Rollout

1. Transparent listener in `proxy/`, with `test/proxye2e` cases: raw TLS with
   SNI to a registry host, origin-form HTTP, a non-registry host spliced. No
   BPF. About 400 lines.
2. `internal/netenforce` contract and Linux implementation, `--enforce` and
   config, state and status, and an e2e test behind
   `//go:build linux && ebpf_e2e` that runs under `sudo` on `ubuntu-latest` in
   `persistent-proxy-e2e.yml`. About 900 lines of Go and 250 of C.
3. `action.yml` input, `persistent-proxy.md` update, a systemd unit example,
   and an acceptance script with a `catalog.yaml` row. The acceptance suite
   checks trust for each supported package manager in enforce mode.
4. Privilege drop: attach as root, serve as the invoking user.

## Decisions needed

1. Root daemon in the first version, with the privilege drop as a follow-up.
   The CA keypair moves to `/etc/safedep/pmg/` in enforce mode.
2. Default eligibility for the action: every user, with computed exemptions.
   Self-hosted operators set `eligible_users` themselves.
3. Commit the compiled BPF object with a CI reproducibility check, or build
   it at release time. I recommend committing it.
