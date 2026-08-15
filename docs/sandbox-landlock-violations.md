# Landlock Sandbox: Violation Diagnostics (Design)

Design for extending `pmg sandbox violations list` / `explain` / `allow` to the Linux
Landlock driver. Today these work on macOS (Seatbelt) only. Bubblewrap is out of scope.

Developer notes for the driver itself: [sandbox-landlock.md](./sandbox-landlock.md).

## Goal

Same developer experience on Linux as macOS: when a sandboxed package manager is denied an
operation, PMG records a `ViolationReport`, and the user can inspect it and get an actionable
`--sandbox-allow` suggestion.

```
$ pmg sandbox violations list
RECORDED              SANDBOX   PROFILE   KIND       TARGET
2026-07-22T...Z       landlock  npm       fs_write   /home/u/.config/foo
```

## How it works today (macOS / Seatbelt)

The pipeline is **capture → cache → present**, cleanly layered:

1. **Capture** (`seatbelt_diagnostics_darwin.go`) — out-of-band. The Seatbelt policy emits
   `PMG_SBX|run=<id>|kind=<k>|target=<t>` markers to the macOS unified log. After `cmd.Run()`
   fails, `seatbeltSandbox.BestEffortViolation(err)` queries `/usr/bin/log show`, filters by
   the run's `logTag`, and parses markers into `[]sandbox.Violation`.
2. **Cache** (`sandbox/executor/diagnostics.go`) — `ObserveViolations` (called from
   `internal/runner/execute.go`) writes the `ViolationReport` to
   `violation-<ts>-<id>.json` via `ViolationCache`. Failures are logged and swallowed;
   observability MUST NOT affect command exit.
3. **Present** — `sandbox/violation.go` (`BuildExplanation` / `scoreViolation` /
   `overrideSuggestion`) is **platform-neutral**: ranks the primary violation, suggests an
   override. `cmd/sandbox/violations_list.go`, `explain.go`, `allow.go`, and
   `internal/ui/sandbox_violation.go` render it.

Dispatch is via the `violationReporter` interface (`sandbox/sandbox.go`):
`ExecutionResult.BestEffortViolation` type-asserts the driver. **`landlockSandbox` does not
implement it, so it returns `nil`** — that is the entire presentation-side gap.

## Why Landlock is different

Landlock LSM **has no violation reporting** — a denied access just returns `EACCES` to the
syscall. There is no log to query (native Landlock audit only landed in kernel 6.15+, too new
to depend on). The Seatbelt "query a log after the fact" model cannot be ported directly.

But the Linux driver is a **hybrid**: Landlock (filesystem allow-list via `RestrictPaths`)
plus a **seccomp-notify supervisor** (`landlock_seccomp_linux.go`) that intercepts
`openat/openat2/execve/execveat`. The supervisor is a userspace process that *sees every deny
decision it makes* and **already emits audit events**:

```go
_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
    Type: auditSeccompDeny, Syscall: ..., Path: resolved, PID: ...,
})
```

The transport already exists too. `landlockSandbox.Execute` opens a `--audit-socket` unix
socket; the helper (`landlock_helper_linux.go`) dials it and uses it as `auditWriter`. The
parent currently **discards** the stream:

```go
go func() {
    conn, _ := listener.Accept()
    io.Copy(io.Discard, conn) // ← events dropped here
}()
```

The original author anticipated this: *"Passes an audit unix socket path for future audit
event consumption."* We are ~70% wired already.

## The core asymmetry (what drives the phasing)

| Policy input | Enforced by | Audit event emitted today? |
|---|---|---|
| `DenyPaths` (`.env`, `.ssh`, …) | seccomp supervisor | ✅ yes |
| `DenyExecPaths` (blocked binaries) | seccomp supervisor | ✅ yes |
| `FilesystemRules` (Landlock allow-list) | **Landlock kernel** | ❌ no |

When an `openat` outside the allow-list is intercepted, the supervisor sees it is not in
`DenyPaths`, calls `respondContinue`, and **Landlock** then returns `EACCES` — no event is
emitted. So the everyday friction case ("npm tried to write outside the project dir") is
**invisible** to the audit stream, while the security-sensitive denies are already captured.

This split is exactly the phase boundary.

---

## Phase 1 — Wire the audit socket (security-sensitive denials)

Captures `DenyPaths` / `DenyExecPaths` hits and all `execve` denials. Low effort, no
enforcement changes, no perf impact.

### Parent side — `sandbox/platform/landlock_linux.go`

- Store `policyName` on `landlockSandbox` (mirror Seatbelt's `s.policyName`); set it in
  `Execute` from `policy.Name`.
- Replace the `io.Discard` goroutine with a **collector**: decode the newline-delimited
  `auditEvent` JSON stream into a slice guarded by a mutex, signal completion on a `done`
  channel, and **cap** the number retained (bound memory against retry-loop floods; log when
  the cap is hit rather than truncate silently — see CLAUDE.md "No silent caps").

### Parent side — new `sandbox/platform/landlock_diagnostics_linux.go`

- Implement `BestEffortViolation(err error) (*sandbox.ViolationReport, error)` on
  `landlockSandbox` (satisfies `violationReporter`). On `err == nil` return `nil`. Otherwise
  wait for the collector `done` (short timeout, e.g. 1–2s), then translate:

  ```
  ViolationReport{
    SandboxName:   sandbox.DriverLandlock,
    PolicyName:    s.policyName,
    CorrelationID: s.socketPath,
    Violations:    translated,
  }
  ```

- Translator `auditEvent → sandbox.Violation` (pure, unit-testable without a kernel):
  - `execve` / `execveat` → `ViolationKindExec`
  - `openat` / `openat2` → `ViolationKindFSRead` or `ViolationKindFSWrite` (needs the access
    mode — see enrichment below)
  - `Path` → `Target`; set `Process` from `PID` best-effort; `RawLog` from the JSON line;
    `RuleLabel` via a `summarizeLandlockViolation` helper mirroring the Seatbelt summarizer.
  - **Dedup by (kind, path)** with a count — seccomp fires per attempt; retry loops repeat.

### Supervisor side — `sandbox/platform/landlock_seccomp_linux.go`

- Enrich `auditEvent` with the access mode so `openat` maps to read vs write. `handleOpen`
  already computes `flags` via `classifyOpenFlags`; add e.g. `Access string`
  (`"read"`/`"write"`/`"both"`) or a pre-normalized kind field. `execve` needs no mode.

### Timing / synchronization

Process tree: `pmg main` → (`cmd.Run()`) → `pmg __landlock_sandbox_exec` (helper, dials
socket) → shim → target. The helper closes its conn on `os.Exit`, so the parent's accepted
conn hits EOF *after* `cmd.Run()` returns. `BestEffortViolation` runs after `cmd.Run()`, so it
must **wait on the collector `done` channel** (bounded) before building the report to avoid
racing the final buffered reads.

### Presentation — mostly free

- `overrideSuggestion` already handles `FSRead` / `FSWrite` / `Exec`, so `--sandbox-allow`
  hints work with no change.
- **Touch-up:** `isNoisySystemPath` (`sandbox/violation.go`) is hardcoded to `DriverSeatbelt`.
  Add Landlock noise paths (`/etc/ld.so.cache`, `/proc/*`, shared-library dirs) so ranking
  stays clean once Phase 2 increases event volume.

### Tests (Phase 1)

- Pure unit tests for the translator + dedup (no kernel needed).
- Extend `sandbox/platform/landlock_e2e_linux_test.go`: deny a `.env`-style path, assert a
  `ViolationReport` is produced and cached.

---

## Phase 2 — Observe Landlock allow-list misses (full fs parity)

Captures the common "write/read outside the allow-list" case.

### Idea

The supervisor already intercepts `openat`; extend it to **observe** allow-list misses without
changing enforcement. Pass the effective allow-list (`FilesystemRules`) into `seccompPhase`.
On each intercepted `openat`, in addition to the `DenyPaths` check, compute *"would Landlock
deny this?"* (path not covered by the allow-list for the requested access mode). If so, emit an
`auditEvent` and still `respondContinue` — **Landlock remains the enforcer**; seccomp only
observes.

### Cost and gating

The per-`openat` interception cost is **already paid today** in practice. `interceptOpen` is
driven by `len(policy.DenyPaths) > 0` (`landlock_shim_linux.go`), and
`landlockTranslatePolicy` unconditionally injects the mandatory credential denies (`.env`,
`.ssh`, `.aws`, …) into `DenyPaths` (`GetMandatoryDenyPatterns`). So for every realistic
policy `openat`/`openat2` already round-trips to the supervisor on every open.

Given that, Phase 2's marginal cost per intercepted `openat` is **one extra userspace
allow-list prefix match, reusing the path already read and resolved for the deny check** — no
new syscalls, no new `/proc` reads, no new context switches. The only genuinely new cost is
emitting an audit event on an allow-list *miss*, which scales with the number of denials (not
opens) and is bounded by the Phase 1 dedup + event cap.

The one case that *does* add interception is a policy with a genuinely empty `DenyPaths` (every
mandatory deny explicitly allowed away — rare/artificial). Gate the always-intercept behind a
config/flag (e.g. a diagnostics/"explain" mode) so that edge case keeps today's performance;
for everyone else the gate is effectively free.

Note: the existing per-open seccomp round-trip is itself the dominant sandbox cost (an
`npm install` can issue hundreds of thousands of opens). Phase 2 rides on it rather than
introducing it; reducing that baseline (batching, BPF-side allow-prefix pre-filtering) is a
separate optimization independent of diagnostics.

### Reuse

The allow-list matching should reuse the translator that builds `FilesystemRules`
(`landlock_translator_linux.go`) rather than reimplementing subtree matching — keep one source
of truth for "is this path allowed" (DRY).

### Tests (Phase 2)

- Extend the E2E to deny an allow-list miss (write outside project dir) and assert the
  `fs_write` violation + a correct `--sandbox-allow write=<path>` suggestion.

---

## Known gaps (parity ≠ identical)

- **Network denials** are not captured — the BPF filter covers only fs/exec syscalls, and
  `network_via_proxy_only` is already unsupported on Landlock. Seatbelt has network violation
  kinds; Landlock will not.
- **memfd fail-open paths** (`handleOpen` when `/proc/<pid>/mem` is unreadable for a
  grandchild) continue silently; such denials stay invisible. Already a documented enforcement
  gap.
- **Bubblewrap** remains without diagnostics (out of scope).

## Summary of changes

| File | Phase | Change |
|------|-------|--------|
| `sandbox/platform/landlock_linux.go` | 1 | Store `policyName`; collector goroutine + `done`/cap |
| `sandbox/platform/landlock_diagnostics_linux.go` (new) | 1 | `BestEffortViolation`, `auditEvent`→`Violation`, dedup, summarizer |
| `sandbox/platform/landlock_seccomp_linux.go` | 1 | Enrich `auditEvent` with access mode |
| `sandbox/violation.go` | 1 | Extend `isNoisySystemPath` for Landlock |
| `sandbox/platform/landlock_seccomp_linux.go` | 2 | Observe allow-list misses; pass allow-list into `seccompPhase` |
| `sandbox/platform/landlock_shim_linux.go` | 2 | Always-intercept `openat` under diagnostics mode (gated) |
| `sandbox/platform/landlock_e2e_linux_test.go` | 1,2 | E2E coverage for both denial classes |
</content>
</invoke>
