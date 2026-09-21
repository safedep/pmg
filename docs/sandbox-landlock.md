# Landlock Sandbox: Developer Notes

This document explains how the Linux Landlock driver works and why it works this way.
The user documentation is in [sandbox.md](./sandbox.md).

## Why Landlock and seccomp

Landlock is an allow-list. Our profiles add deny rules on top of a broad allow. A profile
sets `allow_read: /` and denies `~/.ssh`, `~/.aws`, `.env` and `.git/hooks`. Landlock
cannot remove a path from an allowed subtree. So we add seccomp-notify on top of Landlock.

- Landlock is the kernel allow-list. It is fast and it applies to most syscalls.
- seccomp-notify traps `openat`, `openat2`, `execve` and `execveat`. The supervisor reads
  the path argument from the memory of the trapped process. It matches the path against
  the deny list. It replies `EACCES` or `CONTINUE`. Under network lockdown
  (`network_via_proxy_only`) the filter also traps `connect`, `sendto` and `sendmsg`.
  See "Network lockdown" below.

## Architecture

```
   pmg main ──fork+exec──► pmg __landlock_sandbox_exec      [helper, unfiltered]
                                  │ runs supervisor loop
                                  │
                          clone(CLONE_NEWUSER, uid=host→host)
                                  │
                                  ▼
                           pmg __landlock_shim              [single-threaded,
                            ├ apply Landlock (sets NNP)      non-root uid,
                            ├ install seccomp                no caps;
                            ├ send notify_fd via SCM_RIGHTS  a root caller
                            └ execve target                  maps to uid 65533]
                                  │
                                  ▼
                           target ─► child ─► grandchild    [filter inherited,
                                                             host uid, no caps,
                                                             dumpable=1]
```

The helper has no filter on itself. So the helper can read `/proc/<pid>/mem` of each
descendant to resolve `openat` paths.

### Code layout

| File | Role |
|------|------|
| `cmd/landlock/landlock_sandbox_exec_linux.go` | Helper subcommand wrapper |
| `cmd/landlock/landlock_shim_linux.go` | Shim subcommand wrapper |
| `sandbox/platform/landlock_linux.go` | `Sandbox` implementation, command rewrite |
| `sandbox/platform/landlock_translator_linux.go` | Translates the PMG policy to `landlockExecPolicy` |
| `sandbox/platform/landlock_helper_linux.go` | Helper. Forks the shim and runs the supervisor |
| `sandbox/platform/landlock_shim_linux.go` | Shim. Applies Landlock, installs seccomp, calls execve |
| `sandbox/platform/landlock_seccomp_linux.go` | BPF, supervisor loop, deny matchers, memory reads |
| `sandbox/platform/landlock_abi_linux.go` | Kernel ABI probe |

## Key decisions

### The shim runs in `CLONE_NEWUSER` with an identity uid map

The PID, IPC and mount namespaces need `CAP_SYS_ADMIN`. One `clone()` call creates the
user namespace together with those namespaces, and the kernel checks the capability in the
new user namespace. So the check passes for each uid mapping. The seccomp install needs no
capability, because the shim sets `PR_SET_NO_NEW_PRIVS` first.

The uid maps to itself. Go execs the shim binary as the caller. For a non-root caller that
exec removes all capabilities, and NNP stops each later `execve` from adding any. `id` shows
the caller. npm and pip see the caller. The target cannot use `CAP_DAC_OVERRIDE` on the
files of the caller. The target cannot get `CAP_NET_ADMIN` in a new network namespace.

A root caller maps to uid 65533. A target that sees uid 0 takes root-only code paths. A
tar extractor then restores tarball ownership with `chown`, and a `chown` to an unmapped
uid fails with `EINVAL`. The mapped kuid is still 0, so the target owns the same files as
the root caller. Files that the target creates belong to root on the host. A non-root
`execve` grants no capability, so no `SECBIT_NOROOT` or bounding set handling is needed.

The uid must differ from the kernel overflow id (`/proc/sys/kernel/overflowuid`, 65534 by
default). Each unmapped host uid displays as the overflow id. A target uid equal to it
makes user-space ownership checks answer "mine" for the whole filesystem. One example is
the git "dubious ownership" check. git would accept a repository of a different user and
fail later on the write. The helper reads the overflow ids and picks 65532 when 65533 is
taken.

An earlier design mapped `0 → host_uid`. That design gave uid 0 and all capabilities to the
full target tree. That was not necessary. The helper created the user namespace, so the
kernel grants it `CAP_SYS_PTRACE` over the namespace. With the same uid on both sides, the
helper opens `/proc/<pid>/mem` for each descendant, independent of the dumpable flag.

### The shim applies Landlock and seccomp, Landlock first

An earlier version installed seccomp in the helper and then ran `landlock.RestrictPaths` in
the helper. `BestEffort()` probes the kernel with `openat`. Each probe trapped through the
supervisor in the same process. The Go garbage collector stops the world and needs each
thread at a safepoint. A thread that the kernel holds inside `seccomp_do_user_notification`
cannot get to a safepoint. The helper hung after a small number of notifications.

Now the shim applies both Landlock and seccomp. The shim is a new Go process that has only
one thread at that point. There is no garbage collector pressure during setup. The helper
stays unfiltered. Landlock runs first. Landlock opens each rule path when it builds the
ruleset. If seccomp ran first, the supervisor would deny the shim's own opens against the
deny list.

### The filter does not use `TSYNC`

`SECCOMP_FILTER_FLAG_TSYNC` applies the filter to each thread in the thread group. The Go
runtime threads (garbage collector, sysmon, netpoll) call `openat` often. Each of these
calls would trap and cause the same deadlock as the unsandboxed-helper version. Without
`TSYNC` the filter applies only to the thread that installs it. Descendants inherit the
filter through `clone()` and `execve()`. So we get the same coverage and we do not filter
the Go runtime threads.

### `Stop()` wakes the supervisor with an eventfd

When you close `notifyFd`, the kernel does not wake a thread that blocks in
`ioctl(SECCOMP_IOCTL_NOTIF_RECV)`. The supervisor calls `ppoll` on `notifyFd` and on an
eventfd. `Stop()` writes to the eventfd. See `waitForNotif` in
`landlock_seccomp_linux.go`.

### `landlockReadAccess` includes `EXECUTE`

The `--ro-bind` option of Bubblewrap permits `execve` without a separate rule. Landlock
needs an explicit `AccessFSExecute`. Without it, `allow_read: /` blocks each binary load. So
we put `EXECUTE` into read access. The seccomp supervisor still enforces deny-exec rules.

### The supervisor opens `/proc/<pid>/mem` for each notification and never caches it

An open `/proc/<pid>/mem` file descriptor pins the `mm` of the task at `open()` time. After
an `execve`, a cached descriptor reads the dead address space from before the `execve`. The
reads return EOF and no error. The supervisor sees the `execve` at syscall entry. The kernel
runs the `execve` only after the supervisor replies `CONTINUE`. An open between the reply
and the `mm` switch pins the old `mm`. So the supervisor does not cache. `memFdFor` opens a
new descriptor for each notification. The caller closes it. A thread that waits for a
notification cannot call `execve`. An `execve` kills the other threads. So the open always
pins the live `mm`.

### The deny matcher treats a path as its own subtree

`GetMandatoryDenyPatterns` emits `/home/user/.ssh` without a trailing slash. The matcher
covers the path itself and each path below `entry+"/"`. So the matcher catches
`~/.ssh/id_rsa`. An entry with a trailing slash still matches as a prefix.

### Write denies in a writable project tree go through the supervisor

Landlock has allow rules only. An allow rule on `${CWD}` grants each path below it. No rule
can remove `${CWD}/.env` or `${CWD}/.git/hooks` from that grant. Under the built-in
profiles, only the seccomp supervisor enforces the deny rules for those paths. The
supervisor emulates the path resolution of the kernel and replies inside a TOCTOU window.
Treat these denies as a strong default and not as a hard barrier.

The supervisor traps each syscall that names a path. It matches the canonical path against
the deny list. These edge cases shaped the rules:

- The supervisor denies a rename or hard-link source that is above a deny entry. A move of
  `${CWD}/.git` carries `.git/hooks` with it. The supervisor denies a destination that is
  above an entry. A prepared tree that a process renames onto `.git` replaces `.git/hooks`.
  A symlink follows the destination rule. `mkdir` does not follow it, because `git init`
  must create `.git`.
- `O_RDONLY|O_CREAT` and `O_RDONLY|O_TRUNC` count as writes.
- The supervisor always denies `chroot`. Landlock does not hook it. The target has no
  capabilities, but a nested user namespace gives `CAP_SYS_CHROOT` back.
- The supervisor resolves paths as the kernel resolves them. It resolves a symlink before
  the components after it. It applies `..` after the symlink it follows. It resolves
  `/proc/self` as the process that sent the notification. The walk stops at
  `/proc/<pid>/root`, or at the dirfd under `RESOLVE_IN_ROOT`. `..` stops there and an
  absolute symlink target starts again there.
- The supervisor checks `SECCOMP_IOCTL_NOTIF_ID_VALID` after each `/proc/<pid>` read. So
  it never judges a recycled pid on the state of a different process.
- Deny entries match in lexical form and in canonical form. So `~/.ssh` still matches when
  it is a symlink into a dotfiles checkout.
- A deny glob (`${CWD}/.env.*`, `**/.ssh`) stays a pattern. It covers a file that a process
  creates after setup. A `**/<name>` entry matches the name at each depth, as the Seatbelt
  regex does.

### The filter kills foreign-ABI syscalls

Syscall numbers differ for each ABI. An `int 0x80` or x32 call could reach `openat` under a
number that the filter does not trap. The filter checks `seccomp_data.arch` and, on amd64,
the x32 bit. The filter returns `SECCOMP_RET_KILL_PROCESS`. The kernel does the kill. The
process ends with `SIGKILL` and the supervisor records no violation.

### Network lockdown (`network_via_proxy_only`)

The network rules of Landlock (ABI V4) filter TCP ports only. They cannot match a
destination address. They do not cover UDP. `BindTCP` needs fixed ports, so the dynamic
loopback binds behind `allow_network_bind` cannot be expressed. `network_via_proxy_only` is
a host-and-port contract. So the seccomp supervisor enforces it. The filter traps
`connect(2)`, `sendto(2)` and `sendmsg(2)` when the resolved policy has lockdown on. The
supervisor reads the `sockaddr` from `/proc/<pid>/mem` and applies the same matrix as
Seatbelt:

- Loopback to the PMG proxy port. Allow.
- Any loopback port. Allow when the profile sets `allow_network_bind`.
- Port 53 (TCP or UDP). Allow when the profile sets `allow_direct_dns`.
- Each other non-loopback destination. Deny with `ECONNREFUSED` and a `network_deny`
  audit event. `pmg sandbox violations` shows it as a `network_connect` violation.

A `sendto` or `sendmsg` with a NULL destination address goes to a connected peer. That peer
passed the connect check. The supervisor lets these calls continue without inspection.

Only `AF_INET` and `AF_INET6` go through the matrix. The supervisor allows `AF_UNIX` and
`AF_NETLINK`. They are local IPC and kernel interfaces with no external egress. The
supervisor denies each other family. This includes `AF_VSOCK`, which in a VM can reach host
or guest services outside the proxy.

The filter traps `io_uring_setup` and the supervisor denies it under lockdown. A ring is a
side channel for `IORING_OP_CONNECT` and `IORING_OP_SENDMSG`. These operations never enter
the trapped network syscalls. When the supervisor refuses ring creation, callers go back to
the confined path. io_uring is always optional. Runtimes fall back to epoll or a thread
pool.

**Network denials fail closed when the destination is unknown.** An `openat` also fails
closed when the process memory is unreadable. The supervisor denies a connect when it
cannot verify the destination. Under lockdown an unverifiable destination
looks the same as a hostile one. One example is `dumpable=0` after a hostile `execve`.

**The shim passes its own file descriptor with `sendmmsg`.** The filter traps `sendmsg`.
The shim sends the notify descriptor to the helper (`SCM_RIGHTS`) after the filter
install. The filter applies only to the trapping thread, but a trapped syscall would
deadlock the handoff. Only the listener that the shim is sending can serve the reply. So
the shim passes the descriptor with `sendmmsg(2)`, which is outside the trap set.

### Debugging: `PMG_SECCOMP_TRACE`

Set `PMG_SECCOMP_TRACE=1` to log each intercepted syscall decision at debug level. The log
line has the form `seccomp: allow|deny <syscall> pid=... path|peer=... reason=...`. Use it
with `APP_LOG_LEVEL=debug` and, if you want a file, `APP_LOG_FILE`.

### Network lockdown gaps

These are the known holes in the current enforcement, in approximate priority order:

- **The filter does not trap `sendmmsg(2)`.** The destinations of each message are in an
  `mmsghdr[]` array in process memory. The shim's own handshake uses `sendmmsg`, so we
  accept this blind spot. Resolvers and runtimes rarely use it.
- **The supervisor always allows `AF_UNIX` connects.** On hosts with systemd-resolved,
  glibc NSS resolution reaches the resolver over a unix socket
  (`/run/systemd/resolve/...`). So direct DNS stays reachable with
  `allow_direct_dns: false`. A block needs sockaddr path filtering, which we do not do
  yet. A block without path filtering would break legitimate local IPC. Seatbelt has the
  same problem with mDNSResponder. Seatbelt allow-lists the exact socket paths. The fix
  here is the same.
- **TOCTOU on the sockaddr.** A second thread in the target can rewrite the address
  between the memory read of the supervisor and the `CONTINUE`d syscall in the kernel.
  This is the same class as the `openat` TOCTOU. It is adequate for benign install
  scripts. It is not a hardened defense against a determined escape.
- **The filter does not match 32-bit syscalls.** The filter compares syscall numbers from
  the build architecture. An i386 compat process multiplexes through `socketcall` and
  bypasses the network filter. This gap also applies to the `openat` and `execve` traps.
- **`bind(2)` and `listen(2)` are unrestricted.** This gap is older than lockdown. A
  sandboxed process can listen on any address. The host limits what inbound traffic can
  reach it.

## Go-specific details

The Landlock and seccomp pattern was designed for the C and Rust threading model. Go pays
a constant cost. That cost explains most of the decisions above:

- **Go is multi-threaded from `main()`.** Go always has garbage collector, sysmon and
  netpoll threads. There is no single-threaded mode. `TSYNC` turns those threads into
  traffic for our supervisor.
- **The garbage collector stop-the-world conflicts with a seccomp wait.** A goroutine that
  the kernel holds in a seccomp trap cannot get to a safepoint. The stop-the-world blocks.
  The supervisor goroutine that would release the trap never runs. Rust has no garbage
  collector and no stop-the-world.
- **Go cannot run code between fork and execve.** `exec.Cmd` does `clone()`, a fixed
  sequence, and `execve()`. There is no `PreExecFn` field. The shim subcommand gives us
  the hook that `os/exec` does not have. In Rust this code runs inline after `fork()`.
- **`unshare(CLONE_NEWUSER)` rejects a multi-threaded caller.** A Go program cannot enter
  a new user namespace from `main()`. We create the namespace with `clone(CLONE_NEWUSER)`
  on the child path of `cmd.Start` instead.
- **`runtime.LockOSThread` is mandatory where per-thread state matters.** This applies to
  NNP, the seccomp install, and the `ppoll` and `ioctl` loop of the supervisor. Without
  it the Go scheduler moves the goroutine to a different thread, and the per-thread state
  stays on the wrong thread.

## Limitations

- **Unprivileged user namespaces are required.** On a distribution that disables them,
  `clone()` returns `EPERM`. `NewSandbox` falls back to Bubblewrap only when the Landlock
  ABI probe fails. A `clone()` failure at run time stops the run.
- **The supervisor enforces network lockdown.** `network_via_proxy_only` works through
  seccomp-notify on `connect`, `sendto` and `sendmsg`. See "Network lockdown" above for
  the gaps. We do not use the Landlock port rules (V4+) yet. They would be a race-free
  backstop for the passthrough cases.
- **PID and IPC namespace isolation is best-effort.** On `EPERM` the helper retries
  without these namespaces.
- **A root caller loses `CAP_DAC_OVERRIDE` in the sandbox.** The target runs as uid
  65533 with no capabilities. Permission bits decide each access, even for files that
  root owns. A root-owned directory at mode `0555` rejects a write that real root could
  do. Files of a different user are out of reach.
- **TOCTOU between the path read and the deny reply.** The window is microseconds. A
  process can rewrite the path bytes in its memory, or replace a symlink on disk, after
  the supervisor reads them and before the kernel resolves the path. This is adequate for
  benign install scripts. It is not a hardened defense.
- **A nested user namespace gives capabilities back.** The target has no capabilities
  after `execve`. A process can create a nested user namespace and get capabilities in
  it. The supervisor refuses `chroot`. Landlock refuses mount and `pivot_root`. So no
  known route uses those capabilities.
- **`io_uring` file operations bypass the path traps.** `IORING_OP_OPENAT` and related
  operations never enter the trapped syscalls. The supervisor refuses `io_uring_setup`
  only under network lockdown.
- **The filter does not trap metadata writes.** `chmod`, `chown` and `utimensat` on a
  protected path go through Landlock only. Landlock does not govern them.
