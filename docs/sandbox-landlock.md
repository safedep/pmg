# Landlock Sandbox: Developer Notes

How the Linux Landlock driver works and why. User docs: [sandbox.md](./sandbox.md).

## Why Landlock + seccomp

Landlock is positive allow-list. Our profiles are negative on top of broad allow:
`allow_read: /` plus implicit deny on `~/.ssh`, `~/.aws`, `.env`, `.git/hooks`. Landlock
cannot subtract from a subtree, so we layer seccomp-notify on top:

- Landlock: kernel-native allow-list, fast, applies to most syscalls.
- seccomp-notify: intercepts `openat`/`openat2`/`execve`/`execveat`, resolves the path arg
  by reading the trapping process's memory, matches against the deny list, responds
  `EACCES` or `CONTINUE`. Under network lockdown (`network_via_proxy_only`) it also
  intercepts `connect`/`sendto`/`sendmsg` — see "Network lockdown" below.

## Architecture

```
   pmg main ──fork+exec──► pmg __landlock_sandbox_exec      [helper, unfiltered]
                                  │ runs supervisor loop
                                  │
                          clone(CLONE_NEWUSER, uid=0→host)
                                  │
                                  ▼
                           pmg __landlock_shim              [single-threaded,
                            ├ install seccomp (no NNP)       uid 0 in ns,
                            ├ apply Landlock                 CAP_SYS_ADMIN]
                            ├ send notify_fd via SCM_RIGHTS
                            └ execve target
                                  │
                                  ▼
                           target ─► child ─► grandchild    [filter inherited,
                                                             dumpable=1]
```

The helper has no filter on itself, so it can read `/proc/<pid>/mem` for any descendant
to resolve `openat` paths.

### Code layout

| File | Role |
|------|------|
| `cmd/landlock/landlock_sandbox_exec_linux.go` | Helper subcommand wrapper |
| `cmd/landlock/landlock_shim_linux.go` | Shim subcommand wrapper |
| `sandbox/platform/landlock_linux.go` | `Sandbox` impl, command rewrite |
| `sandbox/platform/landlock_translator_linux.go` | PMG policy → `landlockExecPolicy` |
| `sandbox/platform/landlock_helper_linux.go` | Helper: forks shim, runs supervisor |
| `sandbox/platform/landlock_shim_linux.go` | Shim: installs seccomp+Landlock, execve |
| `sandbox/platform/landlock_seccomp_linux.go` | BPF, supervisor loop, deny matchers, memfd cache |
| `sandbox/platform/landlock_abi_linux.go` | Kernel ABI probe |

## Key decisions

### Shim runs in `CLONE_NEWUSER` so seccomp can be installed without NNP

Unprivileged seccomp install requires `PR_SET_NO_NEW_PRIVS`. NNP plus `execve` triggers
`LSM_UNSAFE_NO_NEW_PRIVS` and the kernel sets `dumpable=0`. With `dumpable=0`,
`/proc/<pid>/mem` opens require `CAP_SYS_PTRACE`, which the helper does not have.
Result: supervisor cannot resolve openat paths for descendants.

The shim boots inside a fresh user namespace mapped `0 → host_uid`. As uid 0 in the ns
it has `CAP_SYS_ADMIN`, which lets seccomp install skip NNP. No NNP, no dumpable reset,
memfd reads work for the whole tree. The mapping preserves host uid for filesystem
ownership; tools that gate on `getuid()` see no change.

### Landlock is applied in the shim, after seccomp install

Earlier the helper installed seccomp first, then ran `landlock.RestrictPaths`.
`BestEffort()` probes via `openat`. Each probe trapped through the supervisor in the
same process. Go's GC stop-the-world needs every thread at a safepoint; a thread
suspended inside `seccomp_do_user_notification` cannot reach one. Helper hung after a
handful of notifications.

Now seccomp + Landlock both live in the shim, which is single-threaded by virtue of
being just-exec'd Go. No GC pressure during setup. Helper is unfiltered.

### No `TSYNC` on the filter

`SECCOMP_FILTER_FLAG_TSYNC` applies the filter to every thread in the group. Go runtime
threads (GC, sysmon, netpoll) routinely `openat`, all would trap and deadlock the same
way the unsandboxed-helper variant did.
Without TSYNC the filter is only on the installing thread. Descendants inherit it via
`clone()` and `execve()` anyway, so we get the same coverage without polluting the Go
runtime threads.

### `Stop()` wakes the supervisor via an eventfd

Closing `notifyFd` does not wake an `ioctl(SECCOMP_IOCTL_NOTIF_RECV)` blocker. We
`ppoll` over `notifyFd` + an eventfd; `Stop()` writes to the eventfd. See
`waitForNotif` in `landlock_seccomp_linux.go`.

### `landlockReadAccess` includes `EXECUTE`

Bubblewrap's `--ro-bind` permits execve implicitly. Landlock requires explicit
`AccessFSExecute`. Without it `allow_read: /` blocks every binary load. We bake EXECUTE
into read access; deny-exec is still enforced by the seccomp supervisor.

### `/proc/<pid>/mem` is opened fresh per notification, never cached

An open `/proc/<pid>/mem` fd pins the task's `mm` at `open()` time, so a cached
fd silently reads the dead pre-exec address space after execve (reads return
EOF). The supervisor learns about execve at syscall-entry, but the exec runs
only after it answers CONTINUE, so an open between the answer and the mm switch
still pins the dying mm. Hence no cache: `memFdFor` opens a fresh fd per
notification and the caller closes it. A parked notifying thread cannot execve
and execve kills sibling threads, so the open always pins the live mm.

### Deny matcher treats a path as its own subtree

`GetMandatoryDenyPatterns` emits `/home/user/.ssh` (no trailing slash). The matcher
covers the path itself and anything beneath `entry+"/"`, so `~/.ssh/id_rsa` is caught.
Trailing-slash entries still prefix-match.

### Write denies under a writable project tree run through the supervisor

Landlock cannot subtract a subpath from a broad grant. When a profile allows
writes to `${CWD}/**` (the default for the built-in package manager profiles),
the Landlock layer permits every write to `${CWD}/.env`, `${CWD}/.git/hooks`
and the other CWD-anchored mandatory deny targets, including rename, link and
unlink. The seccomp supervisor is the enforcement boundary for those paths.

The supervisor traps every syscall that names a path (`seccompPathSyscalls` in
`landlock_seccomp_path_linux.go`): `open`, `creat`, `openat`, `openat2`,
`rename`, `renameat`, `renameat2`, `link`, `linkat`, `unlink`, `unlinkat`,
`rmdir`, `mkdir`, `mkdirat`, `symlink`, `symlinkat` and `truncate`. The legacy
forms exist only on amd64. The rules per operation:

- An open or truncate is denied when the path is a deny entry or below one,
  in the direction the entry denies.
- A remove or create (unlink, rmdir, mkdir, the link path of a symlink) is
  denied when the path is a write-denied entry or below one.
- A rename or hard link is denied when the source is any deny entry, below
  one, or an ancestor of one (moving `${CWD}/.git` carries `.git/hooks` with
  it, and a read-denied file under a new name is readable). The destination
  is denied when it is a write-denied entry, below one, or an ancestor of any
  entry (a prepared tree renamed onto `.git` replaces `.git/hooks`).
  `RENAME_EXCHANGE` applies the source rule to both paths.

The supervisor canonicalizes every path before the match. It resolves the
path component by component like the kernel does: a symlink is followed
before the components after it, `..` applies to the symlink target, and
`/proc/self` names the notifying process, not the supervisor. The final
component is followed for open and truncate, and kept for the syscalls that
act on the link itself. Without this a process could read `${CWD}/.env`
through `ln -s .env x` or through `/proc/self/cwd/.env`.

The deny list is matched in both forms. `Enforce` adds the canonical form of
every deny entry next to its lexical form, so `~/.ssh` still matches when
`~/.ssh` is a symlink into a dotfiles checkout, or when the project lives
under a symlinked home. The lexical form stays for a target that becomes a
symlink after setup.

A deny glob without `**` (`${CWD}/.env.*`) stays a pattern in the deny list.
The supervisor matches it against the path and each of its ancestors at
syscall time, so `.env.local` is covered when the install script creates
it. A `**` pattern is expanded when the policy is built: `dir/**` becomes
`dir`, and a pattern with no base (`**/.env`) is dropped, which is a known
gap of this driver.

### The filter kills foreign-ABI syscalls

The BPF program compares syscall numbers, and those differ per ABI. A process
that enters 32-bit mode (`int 0x80`) or uses the x32 ABI would issue `openat`
under a number the filter does not trap. The filter checks `seccomp_data.arch`
against the native arch and, on amd64, the x32 bit in the number, and returns
`SECCOMP_RET_KILL_PROCESS` for both. Package managers do not ship 32-bit
helpers, so nothing legitimate is lost.

### Network lockdown (`network_via_proxy_only`)

Landlock's own network rules (ABI V4) filter TCP ports only: no destination
matching, no UDP, and `BindTCP` requires concrete ports so the dynamic loopback
binds behind `allow_network_bind` are inexpressible. `network_via_proxy_only`
is a host+port contract, so enforcement lives in the seccomp supervisor:
`connect(2)`, `sendto(2)`, and `sendmsg(2)` trap when the resolved policy has
lockdown on, the supervisor parses the `sockaddr` from `/proc/<pid>/mem` and
applies the Seatbelt-parity matrix:

- loopback to the PMG proxy port: allow
- any loopback port: allow when the profile sets `allow_network_bind`
- port 53 (TCP or UDP): allow when the profile sets `allow_direct_dns`
- everything else non-loopback: deny with `ECONNREFUSED` + a `network_deny`
  audit event, which `pmg sandbox violations` surfaces as a
  `network_connect` violation

`sendto`/`sendmsg` with a NULL destination address target an already-connected
peer (that peer passed the connect check) and continue uninspected.

### Debugging: `PMG_SECCOMP_TRACE`

Set `PMG_SECCOMP_TRACE=1` to log every intercepted syscall decision
(`seccomp: allow|deny <syscall> pid=... path|peer=... reason=...`) at debug
level, alongside `APP_LOG_LEVEL=debug` and optional `APP_LOG_FILE`.

Only `AF_INET`/`AF_INET6` go through the matrix. `AF_UNIX` and `AF_NETLINK`
(local IPC and kernel interfaces, no external egress) are allowed; every other
family is denied, including `AF_VSOCK`, which in a VM can reach host/guest
services outside the proxy.

`io_uring_setup` is trapped and denied under lockdown. A ring is a side channel
for `IORING_OP_CONNECT`/`SENDMSG` that never trips the intercepted network
syscalls; refusing ring creation forces callers back onto the confined path.
io_uring is always optional, so runtimes fall back to epoll/threadpool.

**Network denials fail closed on ambiguity.** Unlike `openat` (which fails open
when process memory is unreadable), a connect is *denied* when the supervisor
cannot verify the destination — under lockdown an unverifiable destination is
indistinguishable from a hostile one (e.g. `dumpable=0` after a hostile execve).

**The shim's own fd-passing uses `sendmmsg`.** The filter traps `sendmsg`, and
the shim's fd handoff to the helper (`SCM_RIGHTS`) happens after filter
install. Only the trapping thread is filtered — but the trapped syscall would
deadlock the handoff (the reply can only be served by the listener that is
itself being sent). The shim therefore passes the fd with `sendmmsg(2)`, which
is outside the trap set.

### Network lockdown gaps

Known holes in the current enforcement, in rough priority order:

- **`sendmmsg(2)` is not intercepted.** Its per-message destinations live in an
  `mmsghdr[]` array in process memory; we lean on it for the shim's own
  handshake and accept the exfiltration blind spot. Rarely used by resolvers
  and runtimes in practice.
- **`AF_UNIX` connects are always allowed.** glibc NSS resolution on
  systemd-resolved hosts reaches the resolver over a unix socket
  (`/run/systemd/resolve/...`), so direct DNS stays reachable even with
  `allow_direct_dns: false`. Blocking this without breaking legitimate local
  IPC needs sockaddr-path filtering we do not yet do. Seatbelt has the mirror
  problem (mDNSResponder) and handles it by allow-listing the exact socket
  paths — the fix here is analogous.
- **TOCTOU on the sockaddr.** Between the supervisor's memory read and the
  kernel executing a `CONTINUE`d syscall, a second thread in the target can
  rewrite the address. Same class as the existing openat TOCTOU; adequate for
  benign install scripts, not a hardened defense against determined escapes.
- **32-bit syscalls are not matched.** The filter compares syscall numbers
  from the build architecture; an i386 compat process multiplexes through
  `socketcall` and bypasses net filtering (pre-existing gap, also true for
  the openat/execve traps).
- **`bind(2)`/`listen(2)` are unrestricted** (pre-existing, unrelated to
  lockdown): a sandboxed process can listen on any address. Inbound acceptance
  is limited by whatever the host exposes.

## Go-specific nuances

The Landlock+seccomp pattern was designed around the C/Rust threading model. Go pays a
constant tax that maps to most of the decisions above:

- **Multi-threaded from `main()`.** Go always has GC, sysmon, netpoll threads. There is
  no single-threaded mode. TSYNC turns those threads into traffic for our supervisor.
- **GC stop-the-world vs. seccomp wait.** A goroutine suspended by the kernel inside
  a seccomp trap cannot reach a GC safepoint. STW blocks. The supervisor goroutine,
  which would unblock the trap, never runs. Rust has no GC, no STW.
- **No code injection between fork and execve.** Go's `exec.Cmd` does
  `clone()` + a hardcoded sequence + `execve()`. There is no `PreExecFn` field. The
  shim subcommand exists to provide a hookpoint that doesn't exist in `os/exec`. In
  Rust this is inline post-`fork()`.
- **`unshare(CLONE_NEWUSER)` rejects multi-threaded callers.** A Go program cannot
  enter a new user namespace from `main()`. We route the namespace through
  `clone(CLONE_NEWUSER)` on the child path of `cmd.Start` instead.
- **`runtime.LockOSThread` is mandatory** wherever per-thread state matters
  (NNP, seccomp install, the supervisor's `ppoll`/`ioctl` loop). Otherwise Go's
  scheduler will move the goroutine and the per-thread state goes with the wrong
  thread.

## Limitations

- **Unprivileged user namespaces required.** On distros that disable them, `clone()`
  returns EPERM. We don't yet probe and fall back to bubblewrap (TODO).
- **Network lockdown enforcement is supervisor-based.** `network_via_proxy_only`
  works via seccomp-notify on `connect`/`sendto`/`sendmsg` (see "Network lockdown"
  above), with the gaps documented there. Landlock-native port rules (V4+) are
  not used yet; they would be a race-free backstop for the passthrough cases.
- **PID/IPC namespace isolation is best-effort.** Retried without on EPERM.
- **Audit events are dropped.** Wired but consumed by `io.Discard`.
- **TOCTOU between path read and deny response.** Microseconds. A process can
  rewrite the path bytes in its memory, or swap a symlink on disk, after the
  supervisor read them and before the kernel resolves the path. Adequate for
  benign install scripts; not a hardened defense.
- **`io_uring` file operations bypass the path traps.** `IORING_OP_OPENAT`
  and friends never enter the trapped syscalls. `io_uring_setup` is refused
  only under network lockdown.
- **Metadata writes are not trapped.** `chmod`, `chown` and `utimensat` on a
  protected path go through Landlock alone, which does not govern them.
