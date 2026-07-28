# PMG Linux Enforcement Layer: eBPF Design Notes

## Goal

- Package registry traffic on a Linux host must not be able to avoid the PMG proxy.
- PMG core continues to work as it does today.
- All Linux specific enforcement lives in an optional, separate layer.
- Targets: CI/CD runners (GitHub Actions) and Linux servers.

## Architecture

```
+------------------------------------------------------+
|  npm / pip / bun / curl / docker builds  (unchanged)  |
+------------------------------------------------------+
|  eBPF enforcement layer          (new, Linux only)    |
+------------------------------------------------------+
|  PMG proxy                       (as today)           |
+------------------------------------------------------+
|  PMG root setup                  (new)                |
+------------------------------------------------------+
```

- Tools layer: package managers, scripts, containers. No changes.
- eBPF layer: ensures registry traffic reaches the proxy.
- Proxy layer: analysis, verdicts, MITM. Unchanged except a new transparent listener.
- Root setup: a single privileged step that installs everything.

## The Enforcement Hook

- The mechanism is an eBPF program attached to a cgroup, on the `connect()` syscall path.
- The kernel runs the program inside the syscall, before any packet exists.
- The program receives a writable context: the destination IP and port the process asked for.
- It has exactly two powers, defined by the kernel:
  1. Return reject. The syscall fails with EPERM. This is **Deny**.
  2. Overwrite the destination, then allow. The kernel connects to the new address. This is **Redirect**.
- Deny and Redirect are two verbs of one hook, not two technologies.

Properties:

- Fires for every process in the cgroup and all its descendants. Containers included.
- Full process context is available: uid, cgroup, pid.
- Requires cgroup v2 and roughly kernel 5.6 or newer.
- Does not require BPF LSM, kernel modules, or a reboot.

## Where the Hook Sits Among eBPF Control Points

```
eBPF network control points
|
+- Socket layer (cgroup hooks)        <- chosen
|    fires inside syscalls (connect, sendmsg, bind)
|    knows the process (uid, cgroup, pid)
|    verbs: deny, rewrite
|    scope: a cgroup and all descendants
|
+- Packet layer (tc / XDP)
|    fires per packet on an interface
|    sees raw bytes (including TLS SNI), not the process
|    verbs: drop, redirect, mangle
|    scope: per interface, per netns (painful with containers)
|
+- LSM layer (BPF LSM)
|    fires at kernel security checkpoints
|    verbs: deny only
|    needs boot time config, absent on GHA runners
|
+- Tracing layer (kprobes, tracepoints)
     sees everything, controls nothing
```

The socket layer is the only one that both knows the process and can rewrite, with no exotic kernel requirements.

## Deny vs Redirect

At connect time only the IP and port are known. No hostname exists yet.
Registry IPs are shared CDN IPs. npmjs sits behind Cloudflare with thousands of other sites.
This asymmetry decides the comparison.

**Deny**

- Policy verb: matching traffic shall not pass.
- Tools must already be configured to use the proxy.
- Decides with incomplete data (IP only).
- A misclassified shared IP breaks an unrelated connection.

**Redirect**

- Routing verb: matching traffic goes through the proxy.
- The tool believes it talks to the registry.
- Over-capture is safe. The proxy reads the SNI and decides with full information.
- Registry name: intercept and analyze.
- Any other name: tunnel through untouched.
- A wrong capture is forwarded correctly, not broken.

Core difference: Deny decides early with bad data. Redirect defers the decision to the proxy, which has good data.

Cost of Redirect: the proxy needs a transparent listener, SNI peeking, and passthrough tunneling.
These are portable Go changes, not platform corner cases.

The verbs compose in one deployment:

- Redirect registry bound TCP to the proxy.
- Deny UDP 443 (QUIC), forcing tools to fall back to TCP, which the proxy can handle.
- Later, optionally: deny all egress outside an allowlist.

## Scenario Matrix

| Scenario | Deny | Redirect |
|---|---|---|
| npm/pip configured for the proxy (today's path) | Works unchanged | Works unchanged, eBPF has nothing to do |
| Proxy unaware tool (bun, cargo, curl install) | Connection refused. Clear failure, tool must be configured | Transparently intercepted. Works if the tool trusts the PMG CA |
| Tool with its own trust store, no PMG CA | Same refusal | TLS certificate error. Confusing failure mode |
| Docker container doing installs | Covered via cgroup inheritance. Fails closed | Covered, but the image lacks the PMG CA. TLS errors. Biggest recurring corner case |
| Shared CDN IP hosting a non registry site | Over-blocks unrelated traffic | Over-captured, SNI shows non registry, tunneled through unharmed |
| Hardcoded IP, DoH, DNS cached before start | Missed (bypass) | Missed (bypass). Closable later with packet layer SNI inspection |
| PMG proxy's own upstream fetches | Must be exempted | Must be exempted, otherwise infinite redirect loop |
| Proxy crashes mid run | Direct access still denied. Fail closed | Redirects hit a dead port. Fail closed. Needs a watchdog |
| QUIC / HTTP3 (UDP 443) | Deny it | Deny it. Tools fall back to TCP |
| Old kernel or cgroup v1 | eBPF unavailable. Fallback or loud refusal | Same |

## Proxy Self Traffic Exemption

Without an exemption, Redirect loops:

```
npm    connect(registry:443) -> hook rewrites -> proxy:8443    intended
proxy  connect(registry:443) -> hook rewrites -> proxy:8443    loop
```

The exemption has three parts:

- Setup time: create a dedicated identity for the proxy. A user (`pmg-proxy`) or a cgroup slice. Start the proxy under it. Write its numeric id into a BPF map.
- Runtime, in kernel: on every connect, the program reads the caller's uid or cgroup id from the kernel and compares it against the map. On match it steps aside.
- Trust: the identity is verified by the kernel. A process cannot claim it without root.

Do not build the exemption on: process name (self declared), pid (recycled), environment variables (trivially set).
The exemption is data in a map consulted by code on every connect, not a one time rule.
A proxy restart is fine as long as it returns under the same identity.

## Trust Boundary Questions

### Q: Does anything other than the proxy need the exempted identity?

No. The exemption must be as narrow as possible.

- Every process holding the identity is invisible to enforcement.
- The only traffic that needs to skip the hook is the proxy's own upstream fetches.
- So the `pmg-proxy` identity exists for exactly one process: the proxy daemon.
- No human user, no other tool, no other PMG component belongs to it.
- Think of it as a service account, like `www-data` for nginx. It exists so the kernel can point at the process, not so anyone can join it.

Acquiring the identity requires root.

- A normal process cannot `setuid(pmg-proxy)` or move itself into the proxy's cgroup slice.
- A malicious script cannot claim "I am the proxy too, exempt me".
- Root put one process inside at setup time and locked the door.

Wanting to exempt a second thing is a design smell. The right fix is to route that thing through the proxy instead.

### Q: cgroup hooks only affect their own cgroup. Can a process escape by moving to a different cgroup?

No. The hook is attached to the root cgroup (`/sys/fs/cgroup`), and two kernel facts make that airtight.

Fact 1: there is no "outside" the root cgroup.

```
/sys/fs/cgroup (root)    <- hook attached HERE
├── system.slice/          (services)
├── user.slice/            (login sessions, shells, npm)
└── docker/<id>/           (containers)
```

- On cgroup v2, every process is in exactly one cgroup.
- Every cgroup is a descendant of the root.
- A hook attached at a node applies to that node and every descendant.
- A process can move between cgroups all it wants. Every destination is still under root, so still under the hook.

Fact 2: the moves are privileged anyway.

- Moving a pid into another cgroup requires write permission on the cgroup filesystem.
- Unprivileged processes do not have that for cgroups they do not own.
- A container gets a cgroup namespace, so it "sees" its own root. That is naming only. Physically its cgroup is still a descendant of the real root, and the hook still fires.

One attach detail makes this watertight: attach with `BPF_F_ALLOW_MULTI`.

- With `ALLOW_MULTI`, a program attached on a child cgroup runs in addition to ours. It cannot replace ours.
- The alternative flag `ALLOW_OVERRIDE` would let a child program supersede the parent's. We do not use it.
- Attaching any cgroup BPF program requires root in the first place.

Escape surface summary:

| Actor | Can they escape the hook? |
|---|---|
| Normal process, any user | No. Every cgroup is under root, and it cannot move itself anyway |
| Process inside a container | No. Its cgroup namespace is cosmetic. Physically still a descendant |
| Process that somehow changes cgroup | No. Still a descendant of root |
| Root | Yes. Root can detach the program entirely. This is the known, accepted boundary |

Both answers reduce to the same rule: only root can change the rules. That is the right place for the boundary, since root is already game over for any host local enforcement.

## Privilege Model

- Root is required once, at setup.
- The proxy must not run as root. It parses hostile network traffic.
- Root performs the setup, then starts the proxy under the unprivileged `pmg-proxy` identity.
- The same identity doubles as the exemption key.

## Setup Stage

```
1. Preflight       kernel version, cgroup v2, BTF present
                   pass: eBPF tier. fail: nftables fallback or loud refusal
2. Identity        create the pmg-proxy user / cgroup slice
3. Trust           install the PMG CA (system store + Node, Python stores)
4. Proxy up        start proxy as pmg-proxy, with the transparent listener
5. Load + attach   programs ship embedded in the pmg binary (CO-RE: one build,
                   many kernels, no compiler, no headers, no kernel module)
                   create maps: registry IP set, exemption ids, event buffer
                   write the pmg-proxy id into the exemption map
                   attach connect4/connect6 (+ UDP hooks) to the root cgroup
6. DNS watcher     agent feeds the registry IP map from observed DNS answers
7. Attestation     record attach time and link handles
                   links are held by the agent, not pinned
                   agent death detaches the hooks, so a gap is provable
```

Teardown mirrors setup: detach, remove maps, emit the final report.

## Registry IP Map

- The hook matches destinations against a BPF map of registry IPs.
- A DNS watcher fills the map by observing DNS answers for registry hostnames.
- This is the only guessing component in the design.
- It misses: hardcoded IPs, DoH resolvers, answers cached before start.
- Redirect tolerates a generous, over-inclusive map. Deny does not.
- See Name Resolution below for why the map can be over inclusive and why SNI, not DNS, is the authoritative source.

## Name Resolution: When the Domain Is Knowable

The destination name is not available at connect time. This is a protocol fact, not a tooling gap.

```
1. app resolves the name       name exists in the app, never passed to the kernel
2. connect() syscall           hook fires here. IP and port only. Zero bytes sent
3. TCP handshake               still no application data
4. client sends ClientHello    SNI first exists on the wire here
5. server certificate
6. encrypted traffic
```

At step 2 the application has already resolved the name and discarded it. The kernel receives four bytes of IP.
Any name recovered at that point is reconstruction from side evidence, and reconstruction is lossy.
At step 4 the client states the name itself, in plaintext, on the exact connection being judged.

### Evidence sources

| Source | Reliability | Read at | Notes |
|---|---|---|---|
| TLS SNI | High | Proxy, or tc packet hook | Client asserted, per connection, RFC 6066, no cache |
| HTTP Host header | High | Proxy | Plaintext HTTP only |
| DNS answers | Medium | tc hook or userspace sniff | Misses cached answers, TTL races, DoH, hardcoded IPs |
| Reverse DNS (PTR) | Not viable | Userspace | Often absent, and never the client's requested name |
| Static IP allowlist | Low | Anywhere | CDN IPs are shared and rotate |

Reverse DNS was measured and rejected. A Cloudflare IP serving example.com returned no PTR record at all.
PTR describes what the address owner published, not what the client asked for.

### Why SNI is dependable

- Standardised as Server Name Indication, RFC 6066.
- Effectively mandatory. A server behind a shared IP needs it to select a certificate.
- Plaintext in the first client message, in both TLS 1.2 and TLS 1.3.
- Bound to one connection. No cache, no TTL, no staleness.
- Sent by every package manager client.

Erosion risks: Encrypted Client Hello, whose adoption is limited and browser led, and a client that lies to a colluding server.
Both sit outside the coverage model. The IP and the process identity are still recorded in either case.

### Consequence for the design

```
connect()      only the IP is known    redirect broadly, accuracy not required
ClientHello    the name is known       decide correctly, at the proxy
```

The decision cannot be made where the data is poor, and it does not need to be.
This is the mechanical reason redirect is the primary verb.

### Original destination recovery

Redirect overwrites the destination address before the connection is made, so that address is lost.

```
npm wants            104.16.11.34:443
hook rewrites to     127.0.0.1:8443
kernel connects to   127.0.0.1:8443
```

The proxy accepts the connection and sees who connected to it. It does not see where that client was trying to go.

This breaks passthrough, which is the reason over capture was safe in the first place.
When SNI shows a non registry name, the proxy must forward the connection to its original destination, and it no longer knows what that was.

| Mechanism | How the proxy learns the original destination |
|---|---|
| nftables REDIRECT | Built in. The kernel records it in conntrack, userspace reads it with `getsockopt(SO_ORIGINAL_DST)` |
| eBPF connect rewrite | Nothing records it. The hook must save the original address into a BPF map before overwriting, and the proxy must look it up |

Cilium keeps the familiar interface by attaching a companion `cgroup/getsockopt` program that answers `SO_ORIGINAL_DST` from the saved map, so proxy code is unchanged from the nftables case.

Open detail: the hook writes the map entry from the client socket, the proxy reads it from its accepted socket.
Both sides must compute the same key for the same connection. Spike this before committing to redirect.

## Fallback: nftables

- Proven transparent proxy mechanism (Istio, mitmproxy): REDIRECT plus SO_ORIGINAL_DST.
- Works on old kernels and cgroup v1 hosts.
- Weaker: no process attribution, clumsier exemption (uid match), conflicts with Docker's iptables rules.
- Role: compatibility tier behind the same interface. Not the primary.
- Not viable alternatives: seccomp (per process opt in), Landlock (cannot filter by destination address).

## Recommendation

- Primary: eBPF Redirect, with the final decision made at the proxy via SNI.
- Proxy runs deprivileged under a dedicated identity, which is also the exemption key.
- DNS watching builds the capture set. Over-capture is harmless due to passthrough.
- nftables as the fallback tier. Loud refusal where neither works.
- The whole layer is optional and Linux only. PMG elsewhere is untouched.

## POC: Network Visibility Milestone

Goal of this stage: prove that a PMG owned process can observe every network connection on the host, attributed to the originating process.
Observation only. No deny, no redirect.

Status: working.

### Setup

A `cgroup/connect4` program writes one record per connect into a ring buffer.
A Go loader attaches it to the root cgroup and drains that buffer.
Built with `cilium/ebpf` and bpf2go, which compiles the C and embeds the bytecode into the Go binary.

| Item | Value |
|---|---|
| VM | OrbStack, Ubuntu 24.04, arm64, kernel 6.17.8 |
| Preconditions | cgroup v2 and BTF both present, so no kernel headers are needed at runtime |
| Go and library | 1.25.1, `github.com/cilium/ebpf` v0.22.0 |
| Build deps | `clang`, `llvm`, `libbpf-dev` |

eBPF runs in the kernel, so build and run both happen inside the Linux VM. macOS is the editor only.

### What each event carries

pid, uid, destination IPv4, destination port, protocol, comm.

Two limits shape how far attribution can go:

- `comm` is capped at 16 bytes by the kernel, so it holds 15 characters. It is a coarse label, not an identity. Node based tools also overwrite it with a truncated command line, for example `npm i safedep-t`. Real binary identity needs `/proc/<pid>/exe` or a content hash, read from userspace.
- No payload exists at connect time, so there is no hostname. See Name Resolution.

Capturing the protocol turned out to be essential. Without it, UDP probes and real TCP connections look identical in the output.

### What the trace showed

One `curl example.com` produced four connects, not one.

```
0.250.250.200:53    UDP   DNS query to the resolver
172.66.147.243:80   UDP   source address selection probe
104.20.23.154:80    UDP   source address selection probe
104.20.23.154:80    TCP   the real connection
```

The UDP probes to web IPs are glibc address sorting (RFC 6724).
A UDP connect sends no packets. It only asks the kernel which route and source address would be used.
Without the protocol field these lines are indistinguishable from real traffic, so capturing `ctx->protocol` is what resolves the ambiguity.

An `npm i` through PMG produced the mediated path end to end:

```
npm i safedep-t  ->  127.0.0.1:34619    TCP   package manager reaching the proxy
pmg              ->  104.16.11.34:443   TCP   proxy fetching upstream
```

The twelve addresses `104.16.0.34` through `104.16.11.34` seen in the trace match the current A records for `registry.npmjs.org` exactly.

### What this proves, and what it does not

Proved:

- Every connect is visible, with process attribution, from a single attach point.
- The mediated path is observable. A package manager reaching the proxy looks different from the proxy reaching the registry.
- The bypass signature is therefore well defined: a non exempt process connecting to an external address instead of the proxy port.

Out of scope at this stage:

- No names, only addresses. See Name Resolution.
- No enforcement. The hook returns allow unconditionally.
- IPv4 only. `connect6` is not attached.
- No UDP 443 handling.

### Self observation is a real failure mode

Adding a reverse DNS lookup inside the event loop created a feedback loop.
The lookup is itself a network operation, so it fired the hook, produced an event, triggered another lookup, and repeated without end.

Two lessons carried into the design:

- The observer must exclude its own traffic. This is the proxy self traffic exemption problem in a smaller form.
- Enrichment must not block the drain loop. A blocked reader stops draining the ring buffer, and the kernel side then drops events.

### Setup gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `directory prefix . does not contain modules listed in go.work` | The pmg repo has a `go.work` that does not list the POC module | `export GOWORK=off` |
| `'asm/types.h' file not found` | `-target bpf` drops the arch include path. Debian multiarch keeps headers under a triplet directory | Pass `-- -I/usr/include/aarch64-linux-gnu` to bpf2go |
| `collect C types: looking up type event: not found` | The type is absent from BTF, or the struct was renamed and `-type` no longer matches | Add the file scope anchor variable. Keep `-type` and the struct name in sync |
| `map create: operation not permitted` | Missing capabilities. The MEMLOCK hint in the message is misleading | Run as root. `rlimit.RemoveMemlock` succeeds without root, map creation does not |

Loading eBPF needs `CAP_BPF` and `CAP_PERFMON`, and distributions ship `kernel.unprivileged_bpf_disabled=2`.

Regenerate after any change to the C struct. The Go struct is generated from it and goes stale otherwise.

### Next steps

1. Exclude the agent's own traffic by pid or uid.
2. Attach `connect6` for IPv6 coverage.
3. Read SNI at a listener to obtain real names.
4. Move from observe to rewrite. Redirect one destination to a local port and confirm the client lands there.
5. Save the original destination into a map so passthrough can recover it.

## CA Trust: Measured Results

Redirect only completes if the captured client trusts the PMG CA. Measured on Ubuntu 24.04 arm64, CA installed with `update-ca-certificates`, no environment variables set anywhere.

### Does the system trust store cover it

| Client | Honours system store | Why |
|---|---|---|
| curl, wget, Go | Yes | linked against system OpenSSL |
| npm, npx (Ubuntu `nodejs` package) | Yes | built with shared OpenSSL |
| pip (Debian packaged) | Yes | Debian patches it to use system certs |
| **npm, npx (nodejs.org, nvm, Docker, GHA)** | **No** | roots compiled into the binary |
| **bun** | **No** | roots compiled in |
| **uv, uvx** | **No** | rustls with webpki-roots |
| poetry | No, not measured | vendored certifi |
| pnpm, yarn | Follows whichever Node runs them | |

The two passing Node and pip rows are distro specific, not tool properties.
GitHub Actions installs Node from nodejs.org, so npm fails there despite passing here.

### Config files close the gap without environment variables

All verified working with no environment variables set:

| Tool | File | Setting | Scope |
|---|---|---|---|
| pip | `/etc/pip.conf` | `cert = <ca>` | system wide |
| uv | `/etc/uv/uv.toml` | `native-tls = true` | system wide |
| npm | `$PREFIX/etc/npmrc` | `cafile=<ca>` | per Node installation |
| bun | `~/.bunfig.toml` | `[install]` then `cafile = "<ca>"` | per user only |

`/etc/bunfig.toml` was tested and is not read.

### Why the config files matter more than they look

`pmg proxy env` emits the CA variables and the proxy variables together.
They are therefore absent in exactly the case the redirect exists for: a client that was never configured.
A CA route independent of the job environment is what makes the redirect worth building.

### Conclusion: three layers

1. System trust store. One call, root is already available at setup. Covers Go, curl, git and distro packaged tooling.
2. Environment variables. Already implemented. Covers everything whenever `pmg proxy env` ran.
3. Config files. Roughly four writes at setup. The only durable route for npm, bun, uv and pip.

Layer 1 is free, layer 2 exists, layer 3 is what makes the redirect pay off.

### Open

- bun has no system level config, so it cannot survive a uid change under `sudo`.
- `$PREFIX/etc/npmrc` is tied to the Node installation, so a later `setup-node` lands on a fresh prefix. Resolve the prefix at setup time, or also write `~/.npmrc`.
- A project level config in the repository overrides all of this. Deliberate act, outside the coverage model, but not closed.
- Containers fail earlier than trust. See below.

## Container Reachability

The hook reaches containers, the redirect target does not.

Measured with `docker run node:20-slim` while redirecting to `127.0.0.1:<proxy>`:

- The container's `node` was captured 12 times: `REDIRECT node 0 -> 104.16.x.34:443`.
- The connection then failed with `ECONNREFUSED`.

`127.0.0.1` inside a container is the container's own loopback, which is empty.
Loopback is network namespaced. The cgroup hook is not.

So "containers included" is half true. Seeing and rewriting work. The rewritten address has to be
valid in the caller's network namespace, which `127.0.0.1` is not.

Options, none implemented:

- Bind the proxy to the bridge address as well, and redirect containers to the bridge gateway.
- Use `bpf_get_netns_cookie()` in the hook to pick a different target per namespace.

Container CA trust is a separate and later problem, since traffic never reaches the proxy today.

## Validate Before Building

1. CA trust inside containers. Redirect's recurring failure mode: images that do not trust the PMG CA fail TLS.
2. Loop exemption. Must be provably airtight under proxy restarts and forks.
3. DNS map fidelity. Measure miss and staleness rates against real npm, pip, bun, uv runs.

## References

Each entry notes what it actually answers, so this stays useful as a lookup rather than a link dump.

### Proxying: explicit vs transparent

- [Broadcom: transparent vs explicit proxies](https://knowledge.broadcom.com/external/article/175723/what-is-the-difference-between-transpare.html).
  The cleanest statement of the difference: an explicit request carries the destination IP of the proxy, a transparent request carries the destination IP of the real server. Everything else follows from that.
- [Cisco WSA: transparent vs forward proxy mode](https://www.cisco.com/c/en/us/support/docs/security/web-security-appliance/117940-qa-wsa-00.html). The same distinction from the deployment side.
- [mitmproxy: how mitmproxy works](https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/).
  Best prose walkthrough of the byte sequence. Builds up explicit HTTP, then explicit HTTPS, then transparent HTTPS. The third section is what this design implements.
- [mitmproxy: transparent proxying howto](https://docs.mitmproxy.org/stable/howto/transparent/) and [proxy modes](https://docs.mitmproxy.org/stable/concepts/modes/). Operational details and the vocabulary the rest of the ecosystem uses.

### TLS and SNI

- [Cloudflare: What is SNI?](https://www.cloudflare.com/learning/ssl/what-is-sni/).
  Why SNI exists: the server must pick a certificate before the client can say over HTTP which site it wants. That chicken and egg problem is the reason the hostname is readable before encryption, and therefore the reason this design can rely on it.
- [Wikipedia: Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication). History and the privacy criticisms.
- [Cloudflare: Good-bye ESNI, hello ECH](https://blog.cloudflare.com/encrypted-client-hello/). The erosion risk noted under Name Resolution, and why encrypting the ClientHello is hard.
- [High Performance Browser Networking, chapter 4](https://hpbn.co/transport-layer-security-tls/). Free online. Handshake round trips, session resumption, ALPN. Read when the handshake itself needs to stop being a black box.

### TLS interception

- [TLSeminar: TLS interception and SSL inspection](https://tlseminar.github.io/tls-interception/).
  Course writeup. Explains the mechanism and, more usefully, what security properties interception gives up.
- [SSL/TLS interception proxies and transitive trust](https://www.grc.com/miscfiles/HTTPS_Interception_Proxies.pdf), Jeff Jarmoc.
  The transitive trust problem: once a CA is installed, the client is trusting the proxy to validate upstream certificates on its behalf. Directly relevant to shipping the PMG CA.
- [The security impact of HTTPS interception](https://jhalderm.com/pub/papers/interception-ndss17.pdf), Durumeric et al., NDSS 2017. Measurement of interception in the wild. Worth skimming before doing this at fleet scale.

### The eBPF hook

- [BPF_PROG_TYPE_CGROUP_SOCK_ADDR](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/).
  The reference for the hook this design uses. Attach types, the writable context struct, return value semantics, kernel version requirements.
- [connect4_prog.c kernel selftest](https://sbexr.rabexc.org/latest/sources/63/661312a89dee55.html).
  A working destination rewrite from the kernel's own test suite. Canonical path is `tools/testing/selftests/bpf/progs/connect4_prog.c`.
- [bpftool-cgroup man page](https://www.mankier.com/8/bpftool-cgroup). Inspecting what is attached where, and the `multi` versus `override` attach flags.
- [BPF_PROG_TYPE_CGROUP_SOCKOPT kernel doc](https://docs.kernel.org/bpf/prog_cgroup_sockopt.html). Different hook, but the clearest official explanation of how multiple programs execute across a cgroup hierarchy under `ALLOW_MULTI`.

### eBPF toolchain

- [ebpf-go getting started](https://ebpf-go.dev/guides/getting-started/). The `cilium/ebpf` and bpf2go workflow used by the POC.
- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples), particularly [cgroup_skb](https://github.com/cilium/ebpf/blob/main/examples/cgroup_skb/main.go) for `link.AttachCgroup`.
- [Learning eBPF](https://www.oreilly.com/library/view/learning-ebpf/9781098135119/), Liz Rice. Program types, maps, CO-RE. Companion examples at [lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf).

### Prior art

- [Envoy TLS Inspector](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/tls_inspector) and [Envoy Original Destination](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/original_dst_filter).
  The two halves of this problem, named and separated: SNI gives the name, `SO_ORIGINAL_DST` gives the address. Reading both makes clear why the original destination gap matters.
- [Cilium: Kubernetes without kube-proxy](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/) and the [Cilium 1.6 announcement](https://cilium.io/blog/2019/08/20/cilium-16/).
  Socket level load balancing is the same mechanism as this design: `cgroup/connect4` rewriting destinations, in production at scale.
- [Harden-Runner: how it works](https://github.com/step-security/harden-runner/blob/main/docs/how-it-works.md).
  Closest product analogue. eBPF hooks installed on a GitHub Actions runner before any workflow step, monitoring and blocking egress by domain.
- [More egress filtering bypasses in harden-runner](https://devansh.bearblog.dev/harden-runner-bypass/).
  Adversarial analysis of a shipped version of this class of control. The cheapest way to learn where it leaks.

### Byte level

- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) and [TLS 1.2](https://tls12.xargs.org/).
  Annotated hex dump of a real handshake. Locate the `server_name` extension inside the ClientHello to see exactly what the proxy's sniffer parses.



---
Step 0: Expose the transparent listener through the CLI

EnableTransparent exists on ProxyConfig but nothing sets it. Needs a flag or config key so pmg proxy start can turn it on.

Verify: start the daemon with it on, connect with a bare tls.Client (no CONNECT), see it work. Basically the test we already wrote, but against the real binary.

---
Step 1: Decision logic in shadow mode

Add the two maps and the full ladder to connect.c, but do not rewrite yet. Instead put a would_redirect flag in the event struct.

- config map: proxy IP + port
- exempt map: uid
- ladder: TCP, not loopback, not exempt, port 443
- Go side: populate both maps, print the decision alongside each event

Verify: run npm i and curl and read the output. Every registry connection should say would redirect, DNS and loopback should say no. If the decisions are wrong here, they'd be wrong destructively in step 2.

This is the cheap safety net: full logic, zero blast radius.

---
Step 2: Turn on the rewrite, aim at a dummy

Flip would_redirect into an actual ctx->user_ip4 / ctx->user_port write. Target a throwaway listener:

nc -l 127.0.0.1 9999

Verify: curl -k https://<some-ip> should hang in nc showing raw TLS bytes instead of reaching the internet. This isolates the rewrite mechanics: byte order, map lookups, the loopback guard. No PMG involved, so a failure here is unambiguous.

---
Step 3: Point it at the real proxy

- Create the pmg-proxy identity
- Start pmg proxy start --daemon under it, transparent enabled
- Read the daemon's address into the config map, its uid into the exempt map
- Attach

Verify, two things:
curl https://example.com          # non-registry → passthrough, real cert
curl https://registry.npmjs.org/  # registry → PMG cert
The first proves the tunnel path and, critically, that the exemption stops the loop. If the loop is broken you'll know instantly because the proxy will spin.

---
Step 4: The demo

unset HTTPS_PROXY HTTP_PROXY     # remove the cooperation path
# keep NODE_EXTRA_CA_CERTS
npm i <package>

Verify: the install succeeds and shows up in PMG's analysis. Then repeat with a known-bad package and confirm it's blocked. That's the claim of the whole layer, demonstrated.

---
Step 5: Coverage gaps

- connect6 for IPv6, which is a live bypass hole until done
- QUIC: deny UDP 443, and note this needs cgroup/sendmsg4 too, since unconnected UDP never hits connect4
- Teardown, and what happens when the proxy dies mid-run

---
