# PMG Linux Network Enforcement

Making package registry traffic on Linux unable to avoid the PMG proxy.

PMG works today by cooperation. It sets proxy configuration, the package manager reads it, and traffic
flows through analysis. That holds as long as the tool cooperates and nobody edits the config. It is a
reasonable default for a developer laptop and a weak guarantee for a fleet.

This document proposes a Linux only layer that removes the cooperation requirement, and works through
what that costs. The target is CI runners and Linux servers, where the environment is uniform and the
kernel is modern. Nothing here changes PMG on macOS or on a developer workstation.

## Contents

- [The gap today](#the-gap-today)
- [Where enforcement can live](#where-enforcement-can-live)
- [Deny or redirect](#deny-or-redirect)
- [Two mechanisms redirect depends on](#two-mechanisms-redirect-depends-on)
- [Can anything escape the hook](#can-anything-escape-the-hook)
- [Privilege and setup](#privilege-and-setup)
- [Corner cases](#corner-cases)
- [If eBPF is not available](#if-ebpf-is-not-available)
- [Open questions](#open-questions)
- [Where the POC stands](#where-the-poc-stands)

---

## The gap today

Every current interception path depends on the tool doing what it is told.

- **Proxy configuration is advisory.** `npm config set proxy ""` or unsetting `HTTPS_PROXY` restores direct access.
- **Shims are positional.** Calling the real binary by absolute path skips them.
- **Unsupported tools are invisible.** `bun`, `uv`, `cargo` and a plain `curl | sh` never consult PMG at all.

None of these require intent. A misconfigured CI step or a tool PMG has not learned about produces the
same outcome as a deliberate bypass: packages enter the build unanalysed, and nothing reports that it
happened.

The goal of this layer is narrow and worth stating precisely. It is not malware containment and not
egress filtering. It is a **coverage guarantee**: if a package reached the build, PMG saw it.

---

## Where enforcement can live

The kernel is the only place a program cannot route around, because every connection is a syscall.
eBPF offers four families of attach point and they differ in what they can see and what they can do.

| Layer | Sees the process | Can block | Can rewrite | Practical catch |
|---|---|---|---|---|
| **Socket (cgroup hooks)** | Yes | Yes | Yes | None on modern kernels |
| Packet (tc, XDP) | No | Yes | Yes | Per interface and per netns, so containers multiply the work |
| LSM (BPF LSM) | Yes | Yes | No | Needs a boot parameter, absent on GHA runners |
| Tracing (kprobes) | Yes | No | No | Observation only |

**The socket layer is the only row with everything we need.** A program attached to a cgroup on the
`connect()` path runs inside the syscall, before a packet exists, and receives both the calling process
identity and a writable destination.

Two properties make it a good fit beyond the table:

- **It ignores network namespaces.** Container workloads inherit the hook through cgroup descent, so a
  container creating its own netns does not escape. The packet layer would need an attachment per interface.
- **It has no exotic requirements.** The connect hooks landed in kernel 4.17. Targeting 5.8 or later also
  gives ring buffers and reliable BTF. Every GHA runner is far above that floor.

What we give up is payload visibility. At connect time there are no bytes to read, which turns out to
drive the entire design.

---

## Deny or redirect

The socket hook offers exactly two verbs, and they are two behaviours of one mechanism rather than two
technologies:

- **Deny.** Return reject and the syscall fails with `EPERM`.
- **Redirect.** Overwrite the destination address, then allow. The kernel connects somewhere else and the
  process never knows.

Choosing between them looks like a policy question. It is really a data question, and one fact settles it:
**at connect time only an IP and a port are known.** Registry traffic terminates on shared CDN addresses,
so `104.16.11.34` is simultaneously npm and a large number of unrelated sites.

**Deny must decide with that.** It has to answer "is this IP a registry?" using an address that is
genuinely ambiguous. When it guesses wrong it breaks an unrelated connection, and the failure surfaces
somewhere far from the cause.

**Redirect does not have to decide.** It can capture generously and hand the connection to the proxy,
which reads the TLS ClientHello and sees the actual hostname. Registry names get intercepted and analysed.
Everything else gets tunnelled through untouched. A wrong capture is forwarded correctly rather than broken.

That asymmetry is the whole argument: **deny decides early with poor data, redirect defers the decision to
the layer that has good data.**

Redirect is not free. The proxy needs a transparent listener that accepts raw TLS, peeks at the SNI, and
can tunnel bytes it does not want to inspect. Those are portable Go changes rather than platform specific
work, which is why the cost is acceptable.

The verbs also compose, so this is not an exclusive choice:

- Redirect registry bound TCP to the proxy.
- Deny UDP 443, since QUIC cannot be intercepted and every client falls back to TCP.
- **[OPEN]** Whether to eventually deny all egress outside an allowlist. That is a different product with a
  different risk profile, and it is not proposed here.

### Why the name is not available at connect time

The argument above rests on a claim worth making explicit, because it constrains every alternative design
as well. The hostname is not merely hard to obtain at connect time. It does not exist yet.

```
1. app resolves the name       the name lives in the app and is never passed to the kernel
2. connect() syscall           the hook runs here. IP and port only. Zero bytes sent
3. TCP handshake               still no application data
4. client sends ClientHello    the name first appears on the wire, in plaintext
5. server certificate
6. encrypted traffic
```

By step 2 the application has resolved the name and discarded it. Any name recovered there is
reconstruction from side evidence. By step 4 the client has stated the name itself, on the exact
connection being judged.

### What the proxy can rely on instead

| Source | Reliability | Where it is read | Why |
|---|---|---|---|
| **TLS SNI** | High | The proxy, or a tc hook | Client asserted, per connection, RFC 6066, no cache to go stale |
| HTTP Host header | High | The proxy | Same property, plaintext HTTP only |
| DNS answers | Medium | tc hook or userspace sniff | Misses cached answers, TTL races, DoH, and hardcoded IPs |
| Reverse DNS | Not viable | Userspace | Frequently absent, and never the name the client asked for |
| Static IP allowlist | Low | Anywhere | CDN addresses are shared and rotate |

Reverse DNS was tested rather than assumed. A Cloudflare address serving example.com returned no PTR
record at all. PTR reports what the address owner published, which is a different question.

**SNI is the dependable source.** It is effectively mandatory, because a server behind a shared address
needs it to choose a certificate, and every package manager client sends it. The erosion risks are
Encrypted Client Hello, whose adoption is limited and browser led, and a client that lies to a colluding
server. Both fall outside the coverage model, and the address and process identity are recorded regardless.

The consequence is that the registry IP map only has to be **good enough to capture**, never accurate
enough to judge. It can be built from observed DNS answers and can over collect safely.

---

## Two mechanisms redirect depends on

Redirect introduces two problems that do not exist in the deny design. Both are solvable and both are
easy to get subtly wrong.

### The proxy must not redirect itself

The proxy fetches from the real registry, which is a connect to the same address the hook is capturing.
Without an exemption it redirects into itself:

```
npm    connect(registry:443) -> rewritten -> proxy:8443    intended
proxy  connect(registry:443) -> rewritten -> proxy:8443    loop
```

The exemption is an identity check the kernel can verify:

- **At setup**, create a dedicated identity for the proxy, either a `pmg-proxy` user or its own cgroup
  slice, start the proxy under it, and write that numeric id into a BPF map.
- **At runtime**, the hook reads the calling task's uid or cgroup id and compares it against the map.
  On a match it steps aside.

The identity must be something the kernel vouches for. Process name is self declared, pids are recycled,
and environment variables are trivially set, so none of them can carry this. A uid or cgroup cannot be
acquired without root, which is what makes the exemption sound.

It should also stay narrow. Every process holding that identity is invisible to enforcement, so exactly
one process gets it. Wanting to exempt something else is a signal that the something else should be
routed through the proxy instead.

### The original destination has to survive the rewrite

Redirect overwrites the destination before the connection is made, which destroys the only record of
where the client was going.

```
npm wants            104.16.11.34:443
hook rewrites to     127.0.0.1:8443
kernel connects to   127.0.0.1:8443
```

The proxy sees who connected to it and not where they intended to go. That breaks passthrough, which is
precisely the property that made generous capture safe.

| Mechanism | How the proxy recovers it |
|---|---|
| nftables REDIRECT | Built in. The kernel records it in conntrack and userspace reads `getsockopt(SO_ORIGINAL_DST)` |
| eBPF connect rewrite | Nothing records it. The hook must save the address into a BPF map before overwriting |

Cilium keeps the familiar interface by answering `SO_ORIGINAL_DST` from a companion `cgroup/getsockopt`
program, so proxy code does not change between the two mechanisms.

**[OPEN]** The map key. The hook writes the entry from the client socket and the proxy reads it from its
accepted socket, so both sides must derive the same key for one connection. This is the first thing to
prove before committing to redirect.

---

## Can anything escape the hook

A cgroup program only affects its own cgroup, which raises the obvious question of whether a process can
simply move somewhere else. It cannot, because the hook attaches to the root.

```
/sys/fs/cgroup (root)      <- attached here
├── system.slice/            services
├── user.slice/              shells, npm, CI steps
└── docker/<id>/             containers
```

On cgroup v2 every process is in exactly one cgroup and every cgroup descends from the root, so a hook at
the root applies everywhere. There is no destination to move to that is outside it. Moving a pid into
another cgroup also requires write access to the cgroup filesystem, which unprivileged processes do not
have. A container gets a cgroup namespace and therefore sees its own root, but that is a naming illusion
and its cgroup remains a descendant of the real one.

One attach detail closes the last gap. Attaching with `BPF_F_ALLOW_MULTI` means a program attached to a
child cgroup runs **in addition to** ours. The alternative flag, `BPF_F_ALLOW_OVERRIDE`, would let a child
supersede the parent, so it is not used. Attaching anything at all requires root.

| Actor | Can it escape |
|---|---|
| Any unprivileged process | No. Every cgroup descends from root, and it cannot move itself anyway |
| Process inside a container | No. The cgroup namespace is cosmetic |
| Root | Yes. Root can detach the program |

Root is the accepted boundary. No host local enforcement survives root, and pretending otherwise would be
dishonest about what this layer provides.

---

## Privilege and setup

Root is needed once, to install. It is not the identity the proxy runs as, for two reinforcing reasons:
a process parsing hostile network traffic should not be root, and the exemption needs a distinct
kernel visible identity anyway.

```
1. Preflight     kernel version, cgroup v2, BTF
                 pass: eBPF tier    fail: nftables fallback, or refuse loudly
2. Identity      create the pmg-proxy user or cgroup slice
3. Trust         install the PMG CA into the system store and per runtime stores
4. Proxy up      start the proxy as pmg-proxy, with the transparent listener
5. Attach        load the embedded programs, create the maps, write the exemption id,
                 attach connect4 and connect6 to the root cgroup
6. Name feed     start the DNS watcher that fills the registry address map
7. Attestation   record the attach time, hold the link handles in the agent
```

Two details in that sequence matter more than they look.

- **Programs ship inside the pmg binary.** CO-RE means one build runs across kernels with no compiler,
  no kernel headers and no kernel module on the target.
- **Link handles are held, not pinned.** If the agent dies the hooks detach with it. That makes a gap in
  enforcement structurally visible rather than silently leaving a half enforcing system behind.

Teardown is the same list in reverse.

---

## Corner cases

| Situation | Behaviour |
|---|---|
| Tool already configured for the proxy | Unchanged. The hook has nothing to do |
| Proxy unaware tool (bun, cargo, curl install) | Transparently intercepted, provided it trusts the PMG CA |
| Tool with its own trust store and no PMG CA | TLS certificate error. Confusing failure, and the main UX risk |
| Container doing installs | Covered by cgroup descent, but the image usually lacks the CA. The most frequent breakage |
| Shared CDN address for a non registry site | Captured, SNI shows a non registry name, tunnelled through unharmed |
| Hardcoded IP, DoH, or DNS cached before start | Missed. Closable later with packet layer SNI inspection |
| Proxy crashes mid run | Redirects hit a dead port, so the build fails closed. Needs a watchdog |
| QUIC on UDP 443 | Denied, so clients fall back to TCP |
| Old kernel or cgroup v1 | eBPF unavailable. Fallback tier, or refuse loudly |

---

## If eBPF is not available

nftables `REDIRECT` with `SO_ORIGINAL_DST` is the proven alternative and is what Istio and mitmproxy use.
It works on old kernels and cgroup v1 hosts.

It is a fallback rather than a peer, because it loses process attribution entirely, makes the proxy
exemption clumsier since only uid matching is practical, and competes with Docker's own iptables rules on
busy hosts. It sits behind the same internal interface so the rest of PMG does not know which tier is active.

Two other mechanisms come up and neither fits. seccomp is per process and opt in, so a bypass simply does
not opt in. Landlock cannot filter on destination address.

---

## Open questions

Architecture is settled: socket layer hook, redirect as the primary verb, decision made at the proxy from
SNI, proxy deprivileged under a dedicated identity, nftables as fallback. What remains open is policy and
a small number of unproven mechanics.

**Policy, deliberately undecided:**

- **[OPEN]** Observe first or enforce immediately. Observation cannot break a build and proves the capture
  set is right before anything is redirected.
- **[OPEN]** Whether a detected bypass fails the build or only reports.
- **[OPEN]** How aggressive the registry address map should be at the start.

**Mechanics to prove before building:**

1. **CA trust inside containers.** Redirect's recurring failure mode. Images that do not trust the PMG CA
   fail TLS, and this is the most likely source of real world breakage.
2. **The exemption, under stress.** It must hold across proxy restarts and forked children.
3. **The original destination map key.** See the redirect section.
4. **Name feed fidelity.** Measure miss and staleness rates against real npm, pip, bun and uv runs.

---

## Where the POC stands

A first milestone is working: a `cgroup/connect4` program attached to the root cgroup, writing one record
per connect into a ring buffer, drained by a Go loader built with `cilium/ebpf`. Observation only, with no
deny and no redirect. Built and run inside an OrbStack Ubuntu 24.04 VM on kernel 6.17.

Each event carries pid, uid, destination address, destination port, protocol and comm.

**What it demonstrated.**

An `npm i` through PMG produced the mediated path end to end, which is the shape enforcement has to preserve:

```
npm i safedep-t  ->  127.0.0.1:34619    TCP    package manager reaching the proxy
pmg              ->  104.16.11.34:443   TCP    proxy fetching upstream
```

The twelve addresses observed in that run match the current A records for `registry.npmjs.org` exactly.
The bypass signature is therefore well defined: a non exempt process connecting to an external address
instead of the proxy port.

**Three findings that changed the design.**

- **Protocol capture is not optional.** A single `curl` produces four connects. One real TCP connection,
  one DNS query, and two UDP probes that glibc uses for source address selection (RFC 6724). Without the
  protocol field the probes are indistinguishable from real traffic.
- **The observer must exclude itself.** Adding a reverse DNS lookup inside the event loop created a
  feedback loop, because the lookup is itself a connect. This is the proxy exemption problem in miniature.
  Enrichment also must not block the drain loop, or the kernel side starts dropping events.
- **`comm` is a label, not an identity.** The kernel caps it at 16 bytes, and Node based tools overwrite it
  with a truncated command line such as `npm i safedep-t`. Real binary identity needs `/proc/<pid>/exe` or
  a content hash read from userspace.

**Not yet covered.** No names, only addresses. No enforcement, since the hook always allows. IPv4 only.
No UDP 443 handling.

**Next.** Exclude the agent's own traffic, attach `connect6`, read SNI at a listener to obtain real names,
then move from observe to rewrite against a local port.
