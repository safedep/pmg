# Container redirect for kernel enforcement

Status: proposal, revision 1. Follows the enforcement design in
[2026-10-03-ebpf-proxy-enforcement-design.md](./2026-10-03-ebpf-proxy-enforcement-design.md),
sections "Known gap: containers" and "Future direction", and the configuration
surface in
[2026-10-03-ebpf-enforcement-config-surface-design.md](./2026-10-03-ebpf-enforcement-config-surface-design.md).
PR #507 and PR #508 implement those two. This spec supersedes the "Future
direction" section where the two differ.

## Problem

Enforcement attaches to the root cgroup, so the kernel programs run for every
process on the host, containers included. The programs route only sockets in
the daemon's network namespace. A socket in any other namespace passes
(`decide`, `ACT_OTHER_NETNS`), because the redirect target is `127.0.0.1`,
and inside a container that address is the container's own loopback.

On GitHub Actions three paths run in another namespace and are not enforced:
`RUN` steps in `docker build`, container jobs, and Docker container actions.
The daemon warns when `dockerd` runs, and the documented workaround puts the
install step in the host namespace with `--network=host`. Container jobs and
Docker actions have no workaround.

The POC verified the fix: every container on every Docker network on the host
reaches the `docker0` address, `172.17.0.1` by default, from the default
bridge, from a user-defined network, and from a `docker build` step.

## Goal

A connection from a container to an enforced port reaches the proxy. A
container that trusts the PMG CA installs through the proxy. A container that
does not trust it fails closed on registry hosts and keeps working on every
other host. Nothing on the host changes for host processes.

## Non-goals

- Putting trust in a container. eBPF cannot change a container's files or
  environment. The CA travels as today, as a build secret or a mount. The
  rejected alternatives are at the end.
- Rootless Docker and Podman. Their containers do not share the host's view
  of a bridge. `mode: ignore` stays correct for them.
- IPv6 in containers. Docker leaves it off by default. A redirected IPv6
  socket in another namespace passes as today until a bridge has an IPv6
  address worth routing to.
- A bridge that appears after the daemon starts. See limits.

## Design

Six changes. The first three make the redirect work. The fourth keeps
container-to-container traffic out of the proxy. The fifth says who is
eligible in a container. The sixth is the switch.

### 1. A second target, chosen by namespace

`struct cfg` gains `bridge_ip4`. `decide` keeps its namespace check, and the
callers of `decide` pick the target:

- a socket in the daemon's namespace goes to `proxy_ip4`, as today;
- a socket in any other namespace goes to `bridge_ip4` when it is set, and
  passes with `ACT_OTHER_NETNS` when it is zero.

The port is the same. One field now. If a third class of socket ever needs
its own target, the field becomes a map keyed by namespace cookie. Nothing in
this design closes that door, and nothing needs it yet.

### 2. A listener on the bridge address

The daemon opens a listener on `bridge_ip4` on the proxy port and passes it in
`AdditionalListenAddrs`, the way the IPv6 loopback listener already travels.
The same handler serves it, and the own-address guard of the transparent
listener already covers every listener the server opened, so a redirected
request that names the bridge listener is refused like one that names
loopback. The daemon binds the bridge address only, never `0.0.0.0`.

### 3. The original destination key gains the address

`orig_dst` is keyed by address family and source port. Every network
namespace has its own port space, so two containers can use the same port at
the same moment. The key becomes family, local address and local port. The
sockops program has the address in `local_ip4` and `local_ip6`. Delivery to a
host address on a bridge is not translated, so the listener sees the same
pair the client socket had.

The buildx `docker-container` builder runs `RUN` steps behind its own NAT, and
the pair changes on the way. The lookup then misses, and the listener falls
back to the server name or the `Host` header, as it does today for any miss.
That is enough for registry hosts.

### 4. Skip the Docker networks

A connection the proxy passes through is dialed by its server name. A
container reaches another container by a name that only Docker's embedded
DNS inside that network resolves, so the proxy cannot dial it. Container
traffic that stays inside Docker's networks is not registry traffic, and it
must not reach the proxy at all.

At attach the daemon reads the host routing table and adds the prefix of
every route over `docker0` or a `br-*` interface to the skip list, next to
the built-in loopback, link-local and metadata entries. `pmg proxy status`
lists them with the other skip destinations. A private registry on the
corporate network is outside those prefixes and stays enforced.

### 5. Users across namespaces

Eligibility works on the kernel uid. Without user namespace remapping,
root in a container is root on the host, and most container processes run as
root. A host policy with `exempt_users: root`, or `eligible_users: runner`,
would leave every container unenforced and reopen the gap under a new name.

A socket in another namespace is eligible regardless of `eligible_users` and
`exempt_users`. The daemon exemption by tgid still applies, because the
programs translate through the PID namespace hierarchy. `exempt_executables`
match by device and inode and do not match container binaries behind an
overlay, so a container has no exemptions. The doc says so.

### 6. Config, flag, variable and input

```yaml
proxy:
  server:
    enforce:
      containers:
        mode: ignore          # ignore | redirect
        bridge_address: ""    # default: the docker0 address at start
```

`containers` is a block, not a scalar, so a later key such as a per-network
rule has a home without a rename. The surface follows the config surface
spec:

- `--enforce-containers <mode>` on `pmg proxy start`, bound to `mode`.
- `PMG_PROXY_SERVER_ENFORCE_CONTAINERS_MODE` and
  `PMG_PROXY_SERVER_ENFORCE_CONTAINERS_BRIDGE_ADDRESS`, which the Viper
  mapping already gives every key.
- `enforce-containers` as an action input, passed as the flag.
- Under `global_lockdown`, `redirect` to `ignore` is a widening flag and is
  refused, like `--enforce-deny-udp=false`.

The state file records the mode and the bridge address. `pmg proxy status`
prints one of:

```
  containers: redirect (bridge 172.17.0.1)
  containers: ignore
  containers: ignore (no bridge at start)
```

The Docker warning keeps its text under `ignore` and goes away under
`redirect`, because the gap is closed. A new one-line warning takes its place
under `redirect`: containers that do not trust the PMG CA fail on registry
hosts.

### Limits

- The bridge address is read once, at attach, from the `docker0` interface.
  A bridge that appears later is not seen, and status says
  `ignore (no bridge at start)`. A netlink watch can lift this later without a
  config change.
- `bridge_address` exists for a changed `bip` or a bridge with another name.
  It is not validated against the routing table beyond being a local address.
- A container reaches the proxy, so it can also send it an explicit `CONNECT`.
  That gives it nothing it lacks, because the same policy decides both paths,
  and it can egress directly today.

## Trust

Unchanged. A redirected connection to a registry host is terminated with a
certificate from the PMG CA. A container that does not trust the CA fails
closed on registry hosts, with the certificate error of its own tool, and
works on every other host, because the proxy passes those through with their
real certificate. The workaround in `docs/persistent-proxy.md` becomes the
way to make a build pass: the CA as a build secret with `NODE_EXTRA_CA_CERTS`,
or the host bundle mounted for tools that replace their bundle. A third-party
Docker action that installs packages fails until its author adds the CA, and
the failure is loud and names the certificate.

## Acceptance

Scripts under `test/acceptance/scripts/enforce/`, each with a catalog row.
`scope/containers-unaffected` becomes the `ignore` case.

| Script | Guarantee |
| --- | --- |
| `scope/containers-ignore` | Under `mode: ignore` a container reaches the registry directly with the real certificate. |
| `scope/containers-redirected-fail-closed` | Under `redirect` a container without the CA gets a certificate error on a registry host and a 200 on a non-registry host. |
| `scope/containers-redirected-trusted` | Under `redirect` a container with the host bundle mounted installs a clean package and is blocked on a malicious one. |
| `scope/containers-build-step` | A `docker build` with `RUN npm ci` fails without the CA and passes with the secret mount from the doc. |
| `scope/containers-to-container-untouched` | Two containers on a user-defined network talk over port 80 by name. |
| `scope/containers-root-not-exempt` | `exempt_users: root` on the host does not exempt a root process in a container. |
| `policy/lockdown-governs-containers` | Under lockdown `--enforce-containers ignore` is refused and `redirect` is accepted. |
| `config/status-names-containers` | Status prints the mode and the bridge address, or the no-bridge note. |

The kernel e2e gains one case: a socket in a new network namespace is routed
to the bridge target and the lookup by address and port returns its original
destination. `test/proxye2e` needs no case, because the handler does not
change.

## Rollout

1. Ship with `mode: ignore` as the default. Status and the Docker warning
   tell every operator the switch exists.
2. One release later, change the default to `redirect`, with a changelog
   entry that names the failure a build without the CA will see. An operator
   who needs time sets `mode: ignore` in the managed config.

## Decisions needed

1. Every socket in another namespace is eligible, regardless of the user
   lists. Recommended: yes. The alternative makes the common CI policy a
   silent bypass.
2. The Docker network prefixes are skipped automatically. Recommended: yes.
   The alternative asks every operator to list their bridges.
3. `containers` is a block with `mode` and `bridge_address`. Recommended:
   yes. A scalar would need a rename for the first extra key.
4. The default changes to `redirect` after one release. Recommended: yes.

## Rejected alternatives

- A SafeDep-hosted registry mirror with a public certificate. It removes the
  CA from the container and replaces it with a registry URL per ecosystem, so
  the configuration step stays. Every download transits SafeDep, the mirror
  becomes a build-critical dependency, and a private registry is out of its
  reach.
- A public certificate for the local proxy on the bridge address. A name that
  resolves to `172.17.0.1` would need a certificate per ephemeral runner,
  past the rate limits of every public CA, and a shared key on every host is
  worse.
- A wrapper around the OCI runtime that adds the CA mount and variables to
  every container. It needs a Docker daemon configuration change and a
  restart, which is more than this feature should own.
