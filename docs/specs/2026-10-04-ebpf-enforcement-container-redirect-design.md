# Container redirect for kernel enforcement

Status: proposal, revision 2. Follows the enforcement design in
[2026-10-03-ebpf-proxy-enforcement-design.md](./2026-10-03-ebpf-proxy-enforcement-design.md),
sections "Known gap: containers" and "Future direction", and the configuration
surface in
[2026-10-03-ebpf-enforcement-config-surface-design.md](./2026-10-03-ebpf-enforcement-config-surface-design.md).
PR #507 and PR #508 implement those two. This spec supersedes the "Future
direction" section where the two differ.

Revision 1 steered container sockets with a second target in the kernel
programs. Revision 2 steers them with nftables at the bridge. The section
"Why revision 2" names what changed and why. The POC under
`scripts/tproxy-poc/` measured every claim below on two kernels and against
Docker 28 on a GitHub runner. Its README has the numbers.

## Problem

Enforcement attaches to the root cgroup, so the kernel programs run for every
process on the host, containers included. The programs route only sockets in
the daemon's network namespace. A socket in any other network namespace
passes (`decide`, `ACT_OTHER_NETNS`), because the redirect target is
`127.0.0.1`, and inside that namespace the address is its own loopback.

The gap is not about containers. It is about network namespaces. Docker,
Podman, nerdctl, kind and a buildx `docker-container` builder all run their
workloads in another network namespace and hand the traffic to the host
through a bridge. On a hosted GitHub runner this leaves `RUN` steps in
`docker build`, `docker run` steps and Docker container actions outside
enforcement. A container job runs every step inside the job container, the
pmg action included, so no daemon exists on the host and that gap closes
only on a self-hosted runner whose host runs the daemon.

Two things cannot be fixed by a better key or a better target in the kernel
programs, and they decided this revision:

- The hook at `connect()` records the address and port the client socket
  has. The listener sees the pair the host receives. Any NAT between the two,
  such as the one inside a buildx `docker-container` builder, rewrites the
  pair, and no lookup can join them. Revision 1 accepted that miss and lost
  every non-standard port behind a nested namespace. `docker/setup-buildx-action`
  creates exactly that builder, so the nested case is the common case in
  Actions.
- The hook cannot tell a Docker network from the internet, so revision 1
  needed a skip list of Docker prefixes with a netlink route watch to keep
  it current.

Conntrack and the routing table already know both answers at the moment a
packet enters the host. This revision asks them.

## Goal

A connection from another network namespace to an enforced port reaches the
proxy. A namespace that trusts the PMG CA installs through the proxy. A
namespace that does not trust it fails closed on registry hosts, with a
message that names the fix, and keeps working on every other host. Host
processes see no change.

## Non-goals

- Trust inside a namespace. Neither eBPF nor nftables can change a
  container's files or environment. The host bundle reaches the container as
  a build secret or a mount, as in part 8. The rejected alternatives are at
  the end.
- Rootless Docker and Podman with pasta or slirp4netns. Their user-mode
  network stack opens host sockets, so their traffic already takes the host
  path through the cgroup programs. Only the trust problem remains for them.
- IPv6 in containers. Docker leaves it off by default. The `inet` table in
  part 1 takes an IPv6 rule later without a new mechanism.
- Steering a virtual machine. A tap or tun ingress is not matched by
  default, because a VM is the same trust problem with a longer path to the
  fix. An operator can name one in `ingress`.
- A change to the host path. Revision 1 made a host connection to a Docker
  network go direct. This revision leaves the host path as it is.

## Design

Eight parts. The first four make the redirect work. The fifth says who is
eligible. The sixth says what happens when the daemon stops. The seventh is
the switch. The eighth is trust and the action.

### 1. Steer at the ingress interface

The daemon owns one nftables table. A nat prerouting chain matches traffic
that enters the host from a bridge and rewrites the destination of an
enforced port to the daemon's listener. This is the ruleset, in `nft` syntax,
for the defaults:

```
table inet pmg {
  flags owner

  chain ingress {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "docker0" jump steer
    iifname "br-*" jump steer
  }

  chain steer {
    fib daddr type local return
    fib daddr oifname "docker0" return
    fib daddr oifname "br-*" return
    tcp dport { 80, 443 } dnat ip to 169.254.200.1:18443
  }

  chain guard {
    type filter hook input priority filter; policy accept;
    ip daddr 169.254.200.1 iifname "lo" accept
    ip daddr 169.254.200.1 iifname "docker0" accept
    ip daddr 169.254.200.1 iifname "br-*" accept
    ip daddr 169.254.200.1 drop
  }

  chain quic {
    type filter hook forward priority filter; policy accept;
    iifname "docker0" udp dport 443 reject
    iifname "br-*" udp dport 443 reject
  }
}
```

The daemon never shells out to `nft`. The GitHub runner image does not ship
the binary. The daemon builds the same rules over netlink with
`google/nftables`. The ports live in a named set, so `nft list table inet
pmg` shows `tcp dport @ports` where this text shows the list.

Why each piece is what it is:

- **A nat chain, not TPROXY.** `nft tproxy` and the xtables `TPROXY` target
  attach the listener socket to the packet with the `sock_edemux`
  destructor. On a host with `bridge-nf-call-iptables=1`, br_netfilter runs
  the IP prerouting hooks during the bridge pass, and `ip_rcv_core` then
  orphans every socket that does not carry `sock_pfree`. The SYN reaches TCP
  with no socket and the kernel resets it. The POC measured this on 6.17
  and 6.18, and read it in the source. br_netfilter supports DNAT in the
  bridge pass by design, so a nat chain works with the setting on or off.
- **`dnat` to one fixed address, not `redirect`.** `redirect` picks the
  ingress bridge's own address, which would need a listener per bridge or a
  listener on `0.0.0.0`. One address the daemon owns needs neither. Part 2
  has the address.
- **`fib daddr type local return`.** A destination on the host is never
  steered. A published port reached through the bridge gateway, and the
  daemon's own listener, stay as they are.
- **`fib daddr oifname ... return`.** A destination that routes back out a
  Docker bridge is never steered, on the same bridge or another one.
  Without this rule the proxy would dial the other container from the
  host, and Docker's isolation between networks, which filters forwarded
  traffic, would never see the connection. These two rules replace the
  route watch of revision 1. The routing table is read per packet, so a
  network that `docker compose up` creates mid-job is covered the moment
  its route exists.
- **`flags owner`.** The table belongs to the daemon's netlink socket, and
  the kernel deletes it when that socket closes. Part 6 has the lifecycle.
- **`ingress` names.** `docker0` and `br-*` are the defaults. The same list
  feeds the `iifname` rules, the `fib` exclusions and the guard. `podman*`,
  `cni*`, `virbr*` or `lxdbr*` are one config line each. The POC confirmed
  that `meta iifkind "bridge"` matches every bridge without a name, but the
  `fib` expression has no `oifkind`, so a kind-based default would need a
  set the daemon keeps in step with the links. Names keep the daemon free of
  any link watch.

### 2. One listener on an address the daemon owns

The daemon adds `169.254.200.1/32` to `lo` at start and removes it at stop.
An address on `lo` is a local address, so a DNAT to it is delivered on the
host from any bridge, with br_netfilter on or off, and the address is not
routable from the LAN. The POC measured this in the emulation on 6.18 and
6.17, and against Docker 28 on a runner, with br_netfilter on and off. The
daemon
opens a listener on that address on the proxy port and passes it in
`AdditionalListenAddrs`, the way the IPv6 loopback listener already travels.
The same handler serves it. The address is configurable for a host that
already uses it.

The `guard` chain drops the address on every ingress but `lo` and the
listed bridges. The own-address guard of the transparent listener already
covers every listener the server opened, so a redirected request that names
this address is refused like one that names loopback. The POC's first runner
leg showed why that guard is not optional: a listener without it dialed
itself in a loop.

The listener accepts only what a redirected client sends: TLS with a server
name, and origin-form HTTP. It refuses a `CONNECT` and an absolute-URI
request, which only a proxy-aware client sends on purpose. A redirected
connection on any listener never dials a destination in the built-in skip
list, so a `Host` header or a server name cannot steer the proxy at the
cloud metadata address.

### 3. The original destination from conntrack

DNAT leaves the pre-NAT destination in conntrack, and the listener reads it
with one `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on the accepted socket. That
is the destination the client wrote, after every inner NAT and before ours.
The POC proved a request to port 8443 through a buildx `docker-container`
builder on the runner.

`lookupOriginalDestination` in `proxy/transparent.go` already receives the
connection. It asks the kernel programs first, as today, and on a miss asks
conntrack. The `orig_dst` map and its key do not change. A miss on both is
what it is today, a proxy-aware client that was never redirected.

### 4. What is not steered

Three cases, all decided by the `steer` chain and all measured against
Docker 28:

- A destination on the host, including a published port on the bridge
  gateway address.
- A container on the same bridge, by address or by Docker's embedded DNS.
- A container on another bridge. Docker's own rules still decide whether
  that traffic passes.

A `--network host` container runs in the daemon's namespace and takes the
host path. Nothing in this table sees it.

### 5. Who is eligible

Every socket outside the daemon's network namespace is steered when its
packets enter through a listed bridge. The user lists and the executable
exemptions of the host path do not apply, because a packet at the bridge
carries no task. Without user namespace remapping, root in a container is
root on the host, so a host policy with `exempt_users: root` would have
exempted every container under a task-based design. The doc says both.

The daemon's own upstream connections leave from the host namespace and
never cross a bridge, so the daemon needs no exemption here.

### 6. Lifecycle and failure

The table carries `flags owner`. The daemon holds one lasting netlink
connection for its lifetime, and the kernel deletes the table when that
connection closes, on `kill -9` and on OOM alike. The POC measured the
deletion. A dead daemon leaves containers with direct egress, the posture
the cgroup programs already have when their links close, and
`docs/persistent-proxy.md` already documents. A clean stop deletes the table
before the listener closes, so an upgrade never leaves rules that point at a
closed port.

A daemon that hangs keeps its connection open, so the table stays and the
listener does not answer. Connections then time out. The loopback listener
has the same gap today, and a watchdog on the listener is the fix for both.
It is not part of this spec.

The probe checks that the kernel accepts an `inet` table with `flags owner`,
which needs 5.13, and that conntrack answers `SO_ORIGINAL_DST`. Every Docker
host has both, because Docker's own NAT runs on them. A host that uses
`iptables-legacy` keeps its rules. Both hook sets run.

The probe runs before the listener opens. Under `redirect` a failed probe
fails the start with the failing check in the message, the way `--enforce`
fails on a host without the BPF features it needs, because an operator who
set `redirect` wants to know that containers are not covered. Under `auto`
a failed probe runs the daemon as `ignore` and records the reason, and
status repeats it. The daemon never creates a table without the owner flag,
because a table that outlives the daemon is a posture this spec does not
ship. `pmg proxy status` prints the table state, and `pmg doctor` reports
a `pmg` table with no daemon behind it as a fault.

### 7. Config, flag, variable and input

```yaml
proxy:
  server:
    enforce:
      namespaces:
        mode: ignore                  # ignore | redirect | auto
        ingress: [docker0, "br-*"]    # interface names, wildcards allowed
        address: 169.254.200.1        # listener address added to lo
```

The values shown are the defaults. `mode` is the only key an operator
sets to turn the feature on. The other two exist for a host that differs
from a Docker host, and the embedded template carries all three with these
values, because that is what makes Viper bind a variable.

- `redirect` means on, and the start fails when the host cannot do it.
- `auto` means on where the probe passes and `ignore` elsewhere, with the
  reason in status. It exists so a later default does not fail the start on
  a host without nftables.
- `ignore` means off.

- `ingress` unset means `docker0` and `br-*`, which covers the default
  bridge and every user-defined network Docker creates. An operator on
  Podman or libvirt adds `podman*` or `virbr*`. A value replaces the list
  and does not extend it, so an operator who adds a name repeats the two
  defaults.
- `address` unset means `169.254.200.1`. The daemon checks at start that
  no interface on the host carries the address, apart from a stale copy of
  its own on `lo` from a crash, which it removes. If another interface has
  it, the daemon under `redirect` fails the start and names the key to set.
  It does not pick another address on its own, because the acceptance
  scripts, the doc and the guard chain name one address.

`namespaces` is a block, so a later key needs no rename. The surface follows
the config surface spec:

- `--enforce-namespaces <mode>` on `pmg proxy start`, bound to `mode`.
- `PMG_PROXY_SERVER_ENFORCE_NAMESPACES_MODE`,
  `PMG_PROXY_SERVER_ENFORCE_NAMESPACES_INGRESS` and
  `PMG_PROXY_SERVER_ENFORCE_NAMESPACES_ADDRESS`. All three keys go in the
  embedded template, which is what makes Viper bind a variable.
- `enforce-namespaces` as an action input, passed as the flag.
- Under `global_lockdown` the parent refuses `--enforce-namespaces ignore`
  and `auto`, as it refuses `--enforce-deny-udp=false`. A mode that can
  degrade on its own is a widening.

Under `redirect` the daemon probes, adds the address, opens the listener
and loads the table in that order, and fails the start if any step fails,
because `redirect` is explicit. The state file records the mode as
configured, the mode in effect, the address and the ingress list, and
status prints one of:

```
  namespaces: redirect (169.254.200.1:18443 from docker0, br-*)
  namespaces: ignore
  namespaces: ignore (auto: nf_tables owner flag refused by the kernel)
```

The Docker warning keeps its text under `ignore`. Under `redirect` a
one-line warning takes its place: a container that does not trust the PMG
CA fails on registry hosts.

### 8. Trust and the action

The capture is transparent. Trust is not, and no capture mechanism changes
that. The proxy terminates a redirected connection to a registry host with
a certificate from the PMG CA, and a client in the namespace that does not
trust the CA fails the handshake. The listener sees the client's
`unknown_ca` alert and logs one line that names the fix, so a build that
fails closed fails with the reason in the daemon log and in
`pmg proxy status`.

`pmg proxy env` prints `PMG_CA_BUNDLE=<path>` under enforcement, in both
modes, next to `REQUESTS_CA_BUNDLE`, from `certmanager.SystemCABundlePath`.
The variable is absent when the host has no bundle. The action needs no
change, because it already appends the output of `pmg proxy env` to
`GITHUB_ENV`. A workflow passes the bundle to a build as a secret and to a
`docker run` as a mount, and never hardcodes a path that differs per
distribution:

```yaml
- run: docker build --secret id=pmg-ca,src=$PMG_CA_BUNDLE -t app .
```

```dockerfile
RUN --mount=type=secret,id=pmg-ca,target=/run/pmg-ca.pem,mode=0444 \
    NODE_EXTRA_CA_CERTS=/run/pmg-ca.pem npm ci
```

`mode=0444` matters, because BuildKit mounts a secret readable by root only
and a Dockerfile with `USER node` could not read it. The bundle, not the CA
alone, is the file to pass. It holds the public roots too. `NODE_EXTRA_CA_CERTS`
adds the file to Node's roots. `PIP_CERT` replaces pip's bundle with the
file. Both work with the bundle. `docs/github-action.md` shows one `RUN`
block that mounts the secret and sets the trust variables from
`EnvVarForProxy` at the mount path, so the doc has one list to keep in step
with the code.

A Docker action gets the workspace mounted at `/github/workspace`, and the
runner passes the step's `env:` into the container. A step before the action
copies the bundle into the workspace, and the variable names the path as the
container sees it:

```yaml
- run: cp "$PMG_CA_BUNDLE" pmg-ca.pem
- uses: some/docker-action@v1
  env:
    NODE_EXTRA_CA_CERTS: /github/workspace/pmg-ca.pem
```

That covers an action that installs packages when it runs. An action with
`image: Dockerfile` that installs packages in a `RUN` step fails closed,
because the runner builds that image at job start and passes no secret. An
action with a prebuilt `image: docker://...` installs nothing on the runner
and is not affected.

### Limits

- A bridge whose name is not in `ingress` is not steered, and nothing warns.
  `pmg doctor` lists the bridges on the host next to the configured names.
- A host firewall with a default deny on input, such as `ufw` on a
  workstation, drops traffic from `docker0` to the host. Every redirected
  container connection is then refused, not only registry ones. The doc
  names the rule to add.
- Any container on a listed bridge gets the host's reachability on the
  enforced ports, for the names it sends. The proxy applies its skip list
  and its own-address guard. It does not apply Docker's network isolation.
- A client that pins its certificate, or keeps its own trust store, fails
  closed on registry hosts under `redirect` with no path to make it pass.

## Trust

Unchanged in substance. A container that does not trust the CA fails closed
on registry hosts, and its tool reports a certificate error. It works on
every other host, because the proxy passes those through with their real
certificate. The workaround in `docs/persistent-proxy.md` becomes the way to
make a build pass: the host bundle as a build secret, named by
`PMG_CA_BUNDLE`, with the trust variables pointed at the mount. Part 8 has
the forms, and the new log line points at the doc.

Under `redirect` the proxy is an egress path for every container on a
listed bridge on the enforced ports, with the host's reachability. Part 2
limits it to redirected traffic and keeps it away from the built-in skip
list. A later `exclude` key in the `namespaces` block can keep a chosen
bridge out of the redirect without a new mechanism.

## Code and maintenance

What the kernel enforcement owns today, on `main`, for scale: 527 lines of
BPF C, 605 lines in `enforcer_linux.go`, about 570 more lines of Go across
the contract, probe, policy and decision files, and 526 lines of kernel
e2e tests.

What this revision adds, by file, with estimates from the POC code:

| Piece | Where | Non-test Go | Tests |
| --- | --- | --- | --- |
| Table, chains and rules over netlink | `internal/netenforce/nft_linux.go` | 180 | 120, rendered rules compared with the text above |
| Owner flag on the table | same file | 0, the library's main branch carries `TableFlagOwner`, pinned as a pseudo-version until a release | in the above |
| Address on `lo`, add and remove | `internal/netenforce/addr_linux.go` | 40, two rtnetlink messages, no new dependency | 30 |
| Conntrack original destination | `proxy/transparent_linux.go` | 40, plus a 10-line stub for other platforms | 40 |
| Listener, status, state, probe and doctor | `internal/proxyserver/enforce.go`, `cmd/proxy` | 120 | 60 |
| Config block, flag, variables, input, lockdown | `config`, `cmd/proxy/enforce_flags.go`, `action.yml` | 80 | 60 |
| Kernel e2e, a bridge and two namespaces as in the POC | `internal/netenforce/e2e_linux_test.go` | 0 | 200 |
| Acceptance scripts | `test/acceptance` | 0 | 9 scripts |

About 500 lines of non-test Go, no BPF C change, one new direct dependency
(`google/nftables`, which brings `mdlayher/netlink`), and about 500 lines of
Go tests plus the scripts. Revision 1 was never built. Its estimate was
about 60 lines of C and 350 lines of Go for the second target, the key
change, the bridge listener and the route watch, plus a kernel e2e case, so
the two revisions cost about the same to write. The difference is what has to be maintained afterwards.
Revision 1 kept a route watch loop, a kernel map in step with it, and a
documented gap for nested namespaces. Revision 2 keeps a ruleset that the
kernel evaluates per packet, and its maintenance is the ruleset text in
part 1 and the e2e that loads it.

The one piece to watch is `google/nftables`. It is a Google project with
releases a year apart. The owner flag landed on its main branch after
v0.3.0, so the daemon pins a pseudo-version until a release carries it. If
the library stalls, the daemon can send the messages the table needs
through `mdlayher/netlink` directly, which is already a dependency. The POC
needed none of this, because it used the `nft` binary, which the daemon
cannot.

## Manual verification

A desktop with Docker is enough. Use a registry host for the fail-closed
check. Any other host is passed through with its real certificate, so
`curl https://ifconfig.co` succeeds with or without the CA and shows the
same address either way, because the container's egress leaves through the
host in both cases. It is the "everything else still works" check, not the
enforcement check.

```sh
# terminal 1
sudo pmg proxy start --enforce --enforce-namespaces redirect
pmg proxy status        # namespaces: redirect (169.254.200.1:18443 from docker0, br-*)

# terminal 2, the rules and their counters, live
sudo watch -n1 nft list table inet pmg

# terminal 3, no trust
docker run --rm -it curlimages/curl sh
curl -sS https://registry.npmjs.org/-/ping    # curl: (60) certificate error
curl -sS https://ifconfig.co                  # passed through, succeeds
curl -sS http://registry.npmjs.org/-/ping     # {} , plain HTTP is steered too
```

Then with the host bundle in the container. The bundle, not the bare CA,
keeps the public roots for the passthrough hosts:

```sh
eval "$(pmg proxy env)"                       # exports PMG_CA_BUNDLE
docker run --rm -it \
  -v "$PMG_CA_BUNDLE":/pmg-ca.pem:ro -e CURL_CA_BUNDLE=/pmg-ca.pem \
  curlimages/curl sh
curl -sS https://registry.npmjs.org/-/ping    # {}
```

`CURL_CA_BUNDLE` is curl's variable. An npm or pip image takes
`NODE_EXTRA_CA_CERTS` or `PIP_CERT`, as in part 8.

Three more checks:

- **Crash.** `sudo kill -9 $(pidof pmg)`. `sudo nft list tables` no longer
  lists `inet pmg`, and the next curl in the container succeeds directly.
  That is the owner flag at work.
- **Hint line.** After the failing curl, the daemon log carries the
  `unknown_ca` line that names `PMG_CA_BUNDLE`. If it does not, part 8 has
  a bug.
- **Not steered.** `docker run --rm --network host curlimages/curl -sS
  https://registry.npmjs.org/-/ping` fails the same way through the cgroup
  programs, and the `steer` counters in terminal 2 do not move.

Two host notes. Arch ships the legacy `iptables` by default, so Docker's
rules live in the legacy tables and ours in nf_tables. Both hook sets run.
`br_netfilter` is often not loaded on a desktop. The redirect path does not
depend on it either way, and `sudo modprobe br_netfilter` before the POC's
tproxy mode shows the failure that decided this revision.

Before the implementation lands, `sudo MODE=dnat ./scripts/tproxy-poc/docker.sh`
runs the same ruleset against a live dockerd. It splices TLS instead of
terminating it, so it proves steering, the exclusions and fail closed, and
not the certificate checks above.

## Acceptance

Scripts under `test/acceptance/scripts/enforce/`, each with a catalog row.
`scope/containers-unaffected` becomes the `ignore` case. The lockdown and
status scripts that exist gain the new assertions instead of new scripts.

| Script | Guarantee |
| --- | --- |
| `scope/namespaces-ignore` | Under `mode: ignore` a container reaches the registry directly with the real certificate. |
| `scope/namespaces-redirected-fail-closed` | Under `redirect` a container without the CA gets a certificate error on a registry host and a 200 on a non-registry host, and the daemon log names the fix. |
| `scope/namespaces-redirected-trusted` | Under `redirect` a container with the host bundle mounted installs a clean package and is blocked on a malicious one. |
| `scope/namespaces-build-step` | A `docker build` with `RUN npm ci` fails without the CA and passes with the secret mount from the doc, with the path read from `pmg proxy env`. |
| `scope/namespaces-nested-builder` | A `docker buildx` build in a `docker-container` builder reaches a registry on a non-standard port through the proxy. |
| `scope/namespaces-to-container-untouched` | Two containers on a user-defined network created after the daemon started talk over port 80 by name, and a container on another network is not reachable through the proxy. |
| `scope/namespaces-root-not-exempt` | `exempt_users: root` on the host does not exempt a root process in a container. |
| `scope/namespaces-no-relay` | A container cannot use the listener as a proxy: a `CONNECT` is refused, and a redirected request with the metadata address as its `Host` is refused. |
| `scope/namespaces-owner-table` | After `kill -9` of the daemon the table is gone and a container reaches the registry directly. |
| `policy/lockdown-governs-widening-flags` | Also: under lockdown `--enforce-namespaces ignore` and `auto` are refused and `redirect` is accepted. |
| `scope/namespaces-redirect-fails-fast` | With nf_tables unavailable, `--enforce-namespaces redirect` fails the start and names the check, and `auto` starts as `ignore` with the reason in status. |
| `status/reports-enforcement` | Also: status prints the mode, the address and the ingress list, and `pmg proxy env` prints `PMG_CA_BUNDLE` for a file that holds the PMG CA. |

The kernel e2e gains the POC's local topology in Go: a bridge, two
namespaces on it, one external namespace behind the host and one nested
namespace behind its own NAT. It loads the table, steers from each
namespace, reads the original destination through conntrack, and checks the
three exclusions. It runs with `bridge-nf-call-iptables` on and off when the
module loads. `test/proxye2e` needs no case, because the handler does not
change.

## Rollout

1. Ship with `mode: ignore` as the default. Status and the Docker warning
   tell every operator the switch exists.
2. One release later, change the default to `auto`, with a changelog
   entry that names the failure a build without the CA will see. An operator
   who needs time sets `mode: ignore` in the managed config, and one who
   wants the start to fail on a host that cannot redirect sets `redirect`.

## Decisions needed

1. Every socket outside the daemon's namespace is steered, regardless of
   the user lists and exemptions. Recommended: yes. A packet carries no task,
   and the alternative makes the common CI policy a silent bypass.
2. The table carries `flags owner`, so the rules die with the daemon.
   Recommended: yes. It matches the posture of the cgroup programs. A plain
   table fails closed and belongs with lockdown, later, if an operator asks.
3. `ingress` is a list of names with wildcards, default `docker0` and
   `br-*`. Recommended: yes. A kind-based match needs a set the daemon keeps
   in step with the links, which is the watch this revision removed.
4. The listener address is `169.254.200.1/32` on `lo`, configurable.
   Recommended: yes. `100.64.0.0/10` collides with Tailscale and
   `192.0.2.0/24` is in use on hosted runners.
5. The default changes to `auto` after one release, and `redirect` stays
   the explicit, fail-fast form. Recommended: yes.

## Why revision 2

The POC tested revision 1's data path against three alternatives.

- **TPROXY on bridge ingress.** Rejected. It fails whenever
  `bridge-nf-call-iptables` is 1, for the kernel reason in part 1. The
  GitHub runner image does not load br_netfilter and Docker 28 does not
  load it, so TPROXY would have passed there and failed on every Kubernetes
  node.
- **A second target in the kernel programs.** Revision 1. It works for a
  container on a bridge and loses non-standard ports behind any inner NAT,
  for the reason in the problem statement. It also needs the route watch
  and the key change.
- **A TC program on each bridge with `bpf_sk_assign`.** Workable, because
  that helper sets `sock_pfree` and survives br_netfilter. It needs an
  attach per bridge, a link watch, and the policy route for the mark, so it
  is more code than the ruleset for the same result. It stays the fallback
  if nftables is ever a firm no.

## Rejected alternatives

- A SafeDep-hosted registry mirror with a public certificate. It removes the
  CA from the container and replaces it with a registry URL per ecosystem, so
  the configuration step stays. Every download transits SafeDep, the mirror
  becomes a build-critical dependency, and a private registry is out of its
  reach.
- A public certificate for the local proxy. A name that resolves to a
  link-local address would need a certificate per ephemeral runner, past the
  rate limits of every public CA, and a shared key on every host is worse.
- A wrapper around the OCI runtime that adds the CA mount and variables to
  every container. It is the only way to make trust transparent. It needs a
  Docker daemon configuration change and a restart, does not reach the inner
  runtime of a `docker-container` builder, and misses a client with its own
  trust store. It stays rejected for this feature and is the first thing to
  revisit if the explicit trust step proves too much for users.
- A listener on `0.0.0.0` with an input guard. It works, and the POC ran
  that way first. One address on `lo` needs no guard on every interface and
  no exposure to explain.
