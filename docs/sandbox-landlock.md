# Landlock Sandbox: Developer Notes

How the Linux Landlock driver works and why. User docs: [sandbox.md](./sandbox.md).

## Why Landlock + seccomp

Landlock is positive allow-list. Our profiles are negative on top of broad allow:
`allow_read: /` plus implicit deny on `~/.ssh`, `~/.aws`, `.env`, `.git/hooks`. Landlock
cannot subtract from a subtree, so we layer seccomp-notify on top:

- Landlock: kernel-native allow-list, fast, applies to most syscalls.
- seccomp-notify: intercepts `openat`/`openat2`/`execve`/`execveat`, resolves the path arg
  by reading the trapping process's memory, matches against the deny list, responds
  `EACCES` or `CONTINUE`.

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

### Per-PID `/proc/<pid>/mem` cache, invalidated on execve

`execve` reshapes the address space; the cached fd returns EOF afterwards. We
invalidate on each execve notification (`seccompPhase.invalidateMemFd`) and lazily
reopen via `memFdFor`. Grandchildren get their own entries.

### Deny matcher treats a path as its own subtree

`GetMandatoryDenyPatterns` emits `/home/user/.ssh` (no trailing slash). The matcher
covers the path itself and anything beneath `entry+"/"`, so `~/.ssh/id_rsa` is caught.
Trailing-slash entries still prefix-match.

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
  returns EPERM. PMG probes the shim path at driver-selection time and falls back
  to Bubblewrap when it cannot work.
- **Host LSM policy must allow the user-ns capability path.** Ubuntu AppArmor can allow
  user namespace creation while denying `CAP_SYS_ADMIN` inside the namespace through the
  `unprivileged_userns` profile. The shim probe catches this before PMG selects Landlock.
- **Network filtering not enforced.** Landlock V4 does TCP ports, not hostnames. Use
  proxy-mode.
- **PID/IPC namespace isolation is best-effort.** Retried without on EPERM.
- **Audit events are dropped.** Wired but consumed by `io.Discard`.
- **TOCTOU between path read and deny response.** Microseconds. Adequate for benign
  install scripts; not a hardened defense.
