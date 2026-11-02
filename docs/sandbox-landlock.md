# Landlock Sandbox: Developer Notes

This document explains how the Linux Landlock driver works and why it works this way.
The user documentation is in [sandbox.md](./sandbox.md).

## Why Landlock and seccomp

Landlock is an allow-list. Our profiles add deny rules on top of a broad allow. A profile
sets `allow_read: /` and denies `~/.ssh`, `~/.aws`, `.env` and `.git/hooks`. Landlock
cannot remove a path from an allowed subtree. So we add seccomp-notify on top of Landlock.

- Landlock provides a kernel allow-list for selected filesystem rights, including open, execution, creation, removal, rename, and version-dependent truncation.
  It does not govern most metadata syscalls.
- seccomp-notify traps `execve`, `execveat`, and the fixed path-syscall table for opens, creation, removal, rename, links, truncation, and chroot.
  amd64 also includes legacy path syscalls.
  See `seccompPathSyscalls` in `landlock_seccomp_path_linux.go`. The supervisor reads
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
                           pmg __landlock_shim              [locked exec thread,
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
| `sandbox/platform/landlock_seccomp_linux.go` | Supervisor loop, exec and network handlers, open and exec deny matchers, memory reads |
| `sandbox/platform/seccomp_filter_linux.go` | Shared BPF filter and installation |
| `sandbox/platform/landlock_seccomp_path_linux.go` | Path syscall table, path resolution, move and write-target checks |
| `sandbox/platform/landlock_seccomp_arch_*.go` | Architecture-specific path and denied syscalls |
| `sandbox/platform/landlock_abi_linux.go` | Kernel ABI probe |

For real-kernel tests, use Linux with Landlock and permitted user namespaces.
Normal test runs skip these cases unless enabled.

```sh
PMG_LANDLOCK_E2E=1 go test -count=1 ./sandbox/platform
```

Use the per-PMG [AppArmor profile](sandbox.md#apparmor-blocks-the-landlock-driver-ubuntu-2310) when host policy blocks namespaces.
A global restriction change used by CI is not a required production setup step.

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
taken. A read failure stops the run. A guess could equal the real overflow id.

An earlier design mapped `0 → host_uid`. That design gave uid 0 and all capabilities to the
full target tree. That was not necessary. The helper created the user namespace, so the
kernel grants it `CAP_SYS_PTRACE` over the namespace. With the same uid on both sides, the
helper can open descendant memory after `PR_SET_DUMPABLE=0`.
A non-root caller has an exception after executing an unreadable binary whose owner is unmapped, such as a root-owned execute-only binary.
The kernel can tie that image to an ancestor user namespace and make it non-dumpable.
The helper then lacks ptrace access there.
The memory open fails, and the supervisor denies the trapped syscall.

### The shim applies Landlock and seccomp, Landlock first

`RestrictPaths` opens rule paths with `openat(O_PATH)` to build the Landlock ruleset.
These opens must run before seccomp starts trapping path calls.
The shim applies Landlock first, then installs the filter on its locked exec thread.
The Go process already has runtime threads.
The helper runs the supervisor in a separate, unfiltered process.

The outer process writes policy and command environment into a same-user temporary JSON file.
The helper reads it, then gives its pathname to the shim for a second read.
Other same-user processes can read the environment in this file.
Another sandboxed run with the shared temp write grant can also alter rules or trap configuration before the shim reopens it.
This race is inferred from the handoff code, not from a reproduced exploit.
Do not treat concurrently sandboxed processes under one user as mutually isolated.

### The filter does not use `TSYNC`

`SECCOMP_FILTER_FLAG_TSYNC` applies the filter to each thread in the thread group.
The filter applies only to the locked thread that calls `execve`.
The target and its descendants inherit it.
`TSYNC` would also filter the shim's other Go runtime threads.
The separate supervisor process avoids the filtered-helper garbage-collector deadlock.

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

The supervisor traps the fixed table of calls that open, create, remove, rename, link, or truncate a path, plus chroot.
It does not trap metadata calls such as chmod, chown, utimensat, xattr, stat, statx, faccessat, readlink, or inotify watch creation. It matches the canonical path against
the deny list. These edge cases shaped the rules:

- The supervisor denies a rename or hard-link source that is above a deny entry. A move of
  `${CWD}/.git` carries `.git/hooks` with it. The supervisor denies a destination that is
  above an entry. A prepared tree that a process renames onto `.git` replaces `.git/hooks`.
  A symlink follows the destination rule. `mkdir` does not follow it, because `git init`
  must create `.git`.
- `O_RDONLY|O_CREAT` and `O_RDONLY|O_TRUNC` count as writes.
- The supervisor always denies `chroot`. Landlock does not hook it. The kernel filter
  refuses a nested user namespace, so the target cannot get `CAP_SYS_CHROOT` back.
- The supervisor resolves paths as the kernel resolves them. It resolves a symlink before
  the components after it. It applies `..` after the symlink it follows. It resolves
  `/proc/self` as the process that sent the notification. The walk stops at
  `/proc/<pid>/root`, or at the dirfd under `RESOLVE_IN_ROOT`. `..` stops there and an
  absolute symlink target starts again there.
- The supervisor checks `SECCOMP_IOCTL_NOTIF_ID_VALID` after each `/proc/<pid>` read. So
  it never judges a recycled pid on the state of a different process.
- Deny entries match in lexical form and in canonical form. So `~/.ssh` still matches when
  it is a symlink into a dotfiles checkout.
- Deny-read and deny-write patterns without `**`, `**/<name>` patterns, and bare `<dir>/**` grants retain coverage of later files.
  `**/<name>` matches the name and its descendants at every depth.
  Seatbelt's equivalent regex matches only the name itself.
- A based globstar with a suffix, such as `${HOME}/**/id_rsa`, expands once at setup.
  It does not cover matching files created later.
  The walk uses a literal suffix comparison.
  `${HOME}/**/*.pem` therefore treats `*.pem` as literal text and can yield no denies without warning.
  The walk stops at 5 levels or 1000 paths.
  A missing base returns the whole base directory and can create a broader deny.
- Every deny-exec glob expands at setup.
  Do not assume it covers a later binary.

Allow globs also expand during setup.
More than 100 matches can widen an allow to its parent directory.
The shim skips a missing rule path.
A later directory needs an existing ancestor grant to receive access.
A bare `base/**` grants the directory inode without a walk and includes later descendants.

Implicit rules grant read-file and execution access to system executable and library directories, read access to `/proc`, access to standard devices, and write access to `os.TempDir()`.
`TMPDIR` can therefore widen a narrow profile's writable area.
PTY-enabled policies also grant PTY paths.
Final deny masking can remove an implicit grant.
Inspect the rendered result before relying on a narrow profile.

### The filter kills foreign-ABI syscalls

Syscall numbers differ for each ABI. An `int 0x80` or x32 call could reach `openat` under a
number that the filter does not trap. The filter checks `seccomp_data.arch` and, on amd64,
the x32 bit. The filter returns `SECCOMP_RET_KILL_PROCESS`. The kernel does the kill. The
process ends with `SIGSYS` (often shown as "Bad system call") and the supervisor records no violation.

### The filter denies kernel attack surface before the traps

Before the traps, the filter refuses syscalls that no package manager needs. The Bubblewrap
driver installs the same filter without the traps (see `seccomp_filter_linux.go`).

- `clone` and `unshare` that create a namespace get `EPERM`. A nested user namespace would
  give the target its capabilities back.
- `clone3` gets `ENOSYS`. BPF cannot read the `clone3` flags struct. glibc then retries
  with `clone`, which the filter can check. Go and musl do not call `clone3`.
- `socket(AF_UNIX)` gets `EACCES` unless the profile sets `allow_unix_sockets`. So does a
  `socketpair` that is not a stream or seqpacket pair. A datagram pair can reach any
  datagram socket with `sendto`, and the kernel makes a `SOCK_RAW` pair a datagram pair.
  Node and libuv use a stream pair for child stdio.
  Python uses pipes, which this rule does not affect.
- A fixed list gets `EPERM`: ptrace and other cross-process memory access, `bpf`,
  `perf_event_open`, `userfaultfd`, the keyring, `io_uring`, kernel modules and `kexec`,
  mount and the new mount API, `setns`, swap, reboot, clock changes, `syslog`, quotas and
  `open_by_handle_at`.
  The list also includes `acct`, `lookup_dcookie`, `fanotify_init`, and `vhangup`.
  amd64 adds `iopl`, `ioperm`, and `uselib`.
  See `seccompDeniedSyscalls` for the complete architecture-specific list.

These denies stop `strace`, `gdb`, rootless containers and nested sandboxes, such as the
Chrome sandbox, inside `pmg sandbox exec`.

### Network lockdown (`network_via_proxy_only`)

Without `network_via_proxy_only`, the Landlock driver supplies no direct network confinement.
A proxy `deny_outbound: ["*:*"]` does not create a network namespace here.
Only traffic that reaches the proxy receives those destination rules.
Bubblewrap differs because it can translate a deny-all profile to `--unshare-net`.
Separate host enforcement can still constrain traffic outside this driver.

The network rules of Landlock (ABI V4) filter TCP ports only. They cannot match a
destination address. They do not cover UDP.
A port rule cannot confine a bind to loopback.
Allowing a connection to a port permits it on every host.
This cannot express arbitrary loopback-only connects required by `allow_network_bind`.
PMG selects at most ABI 5 and does not use the port rules.
`network_via_proxy_only` is
a host-and-port contract. So the seccomp supervisor enforces it. The filter traps
`connect(2)`, `sendto(2)` and `sendmsg(2)` when the resolved policy has lockdown on. The
supervisor reads the `sockaddr` from `/proc/<pid>/mem` and applies the same matrix as
Seatbelt:

- Loopback to the PMG proxy port. Allow.
- Any loopback port. Allow when the profile sets `allow_network_bind`.
- Port 53 (TCP or UDP). Allow when the profile sets `allow_direct_dns`.
- Every other destination, including other loopback ports. Deny with `ECONNREFUSED` and a `network_deny`
  audit event. `pmg sandbox violations list` shows it as a `network_connect` violation.

A `sendto` or `sendmsg` with a NULL destination address goes to a connected peer. That peer
normally passed the connect check.
The untrapped `sendmmsg` path is an exception to that assumption. The supervisor lets these calls continue without inspection.

Only `AF_INET` and `AF_INET6` go through the matrix. The supervisor allows `AF_NETLINK`,
which `getaddrinfo` uses to list interfaces. An `AF_UNIX` connect reaches the supervisor
only when the profile sets `allow_unix_sockets`, because the kernel filter refuses
`socket(AF_UNIX)` otherwise. The supervisor then allows it. A host socket such as the
Docker daemon is a way around the proxy, so `pmg sandbox profile lint` warns about that
pair. The supervisor denies each other family. This includes `AF_VSOCK`, which in a VM can
reach host or guest services outside the proxy.

The kernel filter refuses `io_uring` in every mode. A ring is a side channel for
`IORING_OP_CONNECT`, `IORING_OP_SENDMSG` and `IORING_OP_OPENAT`, which never enter the
trapped syscalls. io_uring is always optional. Runtimes fall back to epoll or a thread pool.

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

On Linux, inspect the translated rules and driver first.

```sh
pmg sandbox profile show exec --driver landlock
pmg sandbox doctor --driver landlock
PMG_SECCOMP_TRACE=1 pmg --debug sandbox exec -- your-program
```

Add `--log <file>` alongside `--debug` for a diagnostic file.
Without `--debug`, PMG disables stdout logging.
For environment-only file logging, set both `APP_LOG_LEVEL=debug` and `APP_LOG_FILE=<file>`.
A `--log` option without `--debug` resets the level to info.
Trace lines begin with `seccomp: allow` or `seccomp: deny`, then a syscall and `pid=`.
Most name the target with `path=` or `peer=`.
A deny uses `rule=`, `access=`, or `reason=` for its cause.
The supervisor does not trace a NULL-destination send or stale notification.

`PMG_KEEP_POLICY` only suppresses helper deletion.
The outer driver's normal cleanup still removes the policy file.
Do not rely on it for post-run retention.
A manually retained policy contains command environment and environment-dependent resolved paths.

### Network lockdown gaps

These are the known holes in the current enforcement, in approximate priority order:

- **The filter does not trap `sendmmsg(2)`.** The destinations of each message are in an
  `mmsghdr[]` array in process memory. The shim's own handshake uses `sendmmsg`, so we
  leave this blind spot in the target too.
  A hostile process can use `sendmmsg` on an unconnected UDP socket to send to any host and port.
  This bypasses `network_via_proxy_only`.
  glibc also uses it for DNS, normally on an already connected socket.
- **`allow_unix_sockets` opens every unix socket.** The kernel filter cannot read a
  socket path, so the choice is all or nothing. With the default, glibc NSS modules that
  use a socket (systemd-resolved, nscd) fail and glibc falls back to files and DNS.
- **TOCTOU on the sockaddr.** A second thread in the target can rewrite the address
  between the memory read of the supervisor and the `CONTINUE`d syscall in the kernel.
  This is the same class as the `openat` TOCTOU. It is adequate for benign install
  scripts. It is not a hardened defense against a determined escape.
- **Loopback DNS remains available when binds are allowed.** A resolver on `127.0.0.53` or another loopback address can forward queries off-host even with `allow_direct_dns` false.
- **`bind(2)` and `listen(2)` are unrestricted.** This gap is older than lockdown. A
  sandboxed process can listen on any address. The host limits what inbound traffic can
  reach it.

## Go-specific details

The Landlock and seccomp pattern was designed for the C and Rust threading model. Go pays
a constant cost. That cost explains most of the decisions above:

- **Go is multi-threaded from `main()`.** The runtime starts sysmon and adds threads for GC work and blocking syscalls.
- **A trap on a raw runtime syscall can block stop-the-world.** A normal Go syscall releases its P.
  Some runtime syscalls, including runtime `openat`, do not.
  If the kernel holds such a call in a trap, stop-the-world can wait indefinitely.
  A supervisor goroutine in the same filtered process cannot resolve that deadlock.
  The supervisor therefore runs in the unfiltered helper.
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
- **PID, IPC, and mount namespaces are best-effort.** On `EPERM` or `EINVAL`, the helper warns and retries without them.
  A profile allowing non-self `/proc` paths skips PID and mount namespace creation.
  PMG drops authored `/proc` read and write denies with diagnostic warnings.
  Even when PID namespace creation succeeds, PMG does not mount a fresh procfs.
  The inherited `/proc` still exposes host process entries subject to Unix permissions.
  PMG does not apply Landlock signal scoping.
  Host signal permission checks and other host controls still apply.
- **ABI limits affect the boundary.** ABI 1 cannot support cross-directory link and rename grants through `REFER`.
  ABI 2 adds that right.
  ABI 3 adds `TRUNCATE`.
  On ABI 1 or 2, a file outside `allow_write` can still be truncated if Unix permissions permit it and no deny path matches.
  The supervisor's truncate check enforces denies, not the full write allow-list.
  Device ioctl control applies only when ABI 5 rights are selected.
  PMG does not select signal scopes from newer ABIs.
- **A root caller loses `CAP_DAC_OVERRIDE` in the sandbox.** The target runs as uid
  65533 with no capabilities. Permission bits decide each access, even for files that
  root owns. A root-owned directory at mode `0555` rejects a write that real root could
  do. Files of a different user are out of reach.
- **A root caller usually has no passwd entry in the sandbox.** The target runs as the
  unmapped uid (65533, or 65532 when the kernel overflow uid is 65533), and `/etc/passwd`
  is the host file. On most hosts that file has no entry for either uid, so `getpwuid`
  fails. A tool that reads the home directory or the user name from `HOME`, `USER` or
  `LOGNAME` first does not notice. npm
  and its lifecycle scripts, pnpm, yarn, pip and uv install as root with the default
  profiles. A tool that looks the uid up directly fails: Node's `os.userInfo()` throws
  `uv_os_get_passwd returned ENOENT`, Python's `pwd.getpwuid(os.getuid())` raises
  `KeyError`, and Go's `user.Current()` in a cgo build returns an error. Keep `HOME` set
  when you run pmg as root. The earlier `0 -> host_uid` map always resolved, and it gave
  the target every capability in the namespace.
- **TOCTOU between the path read and the deny reply.** The window is microseconds. A
  process can rewrite the path bytes in its memory, or replace a symlink on disk, after
  the supervisor reads them and before the kernel resolves the path. This is adequate for
  benign install scripts. It is not a hardened defense.
- **Driver audit capture is bounded.** The helper sends events over a Unix audit socket.
  Connection failure is debug-only and loses captured driver events.
  The driver buffers at most 512 events, including operational events, and deduplicates captured denials.
  Environment scrubs and proxy denials have independent reporting paths.
- **Kernel denials leave no violation record.** The syscalls in the kernel deny list and
  a refused unix socket return an error in the kernel. The supervisor never sees them, so
  `pmg sandbox violations list` does not list them.
- **The filter does not trap metadata writes.** `chmod`, `chown` and `utimensat` on a
  protected path go through Landlock only. Landlock does not govern them.
