//go:build linux

package platform

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/unix"
)

// ioctl constants for seccomp-notify, from Linux kernel UAPI include/uapi/linux/seccomp.h.
// These are _IOWR('!', N, struct) values.
const (
	_SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100
	_SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101
)

// seccomp constants available in golang.org/x/sys/unix, aliased here for clarity.
// unix.SECCOMP_FILTER_FLAG_NEW_LISTENER        = 0x8
// unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV  = 0x20
// unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE        = 0x1
// unix.SECCOMP_RET_USER_NOTIF                  = 0x7fc00000
// unix.SECCOMP_RET_ALLOW                       = 0x7fff0000

// C-layout structs matching kernel seccomp notification structures exactly.

type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// Compile-time size assertions to ensure struct layout matches kernel expectations.
var (
	_ [unsafe.Sizeof(seccompData{}) - 64]byte
	_ [unsafe.Sizeof(seccompNotification{}) - 80]byte
	_ [unsafe.Sizeof(seccompNotifResp{}) - 24]byte
)

// denyMode specifies what kind of access should be denied for a path.
type denyMode int

const (
	denyRead denyMode = iota
	denyWrite
	denyBoth
)

// denyPathEntry pairs a filesystem path with the access mode to deny.
type denyPathEntry struct {
	Path string
	Mode denyMode
}

// auditEventType categorizes security audit events.
type auditEventType string

const (
	auditSeccompDeny          auditEventType = "seccomp_deny"
	auditNetworkDeny          auditEventType = "network_deny"
	auditNamespaceUnavailable auditEventType = "namespace_isolation_unavailable"
	auditMemFdOpenFailed      auditEventType = "memfd_open_failed"
)

// auditEvent represents a single security audit log entry.
type auditEvent struct {
	Type     auditEventType `json:"type"`
	Syscall  string         `json:"syscall,omitempty"`
	Path     string         `json:"path,omitempty"`
	Access   string         `json:"access,omitempty"`
	RulePath string         `json:"rule_path,omitempty"`
	Comm     string         `json:"comm,omitempty"`
	PID      int            `json:"pid,omitempty"`
	Message  string         `json:"message,omitempty"`
	Error    string         `json:"error,omitempty"`
	Ts       int64          `json:"ts"`
}

// writeAuditEvent JSON-encodes an audit event and writes it as a single line to w.
func landlockWriteAuditEvent(w io.Writer, evt auditEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	data = append(data, '\n')

	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}

	return nil
}

// Offsets into struct seccomp_data.
const (
	seccompDataNrOffset   = 0
	seccompDataArchOffset = 4
)

// landlockBuildNotifyFilter builds a classic BPF program returning
// SECCOMP_RET_USER_NOTIF for the given syscalls and SECCOMP_RET_ALLOW for
// everything else. Shared by the shim (which installs it inside the user
// namespace without NNP) and tests.
//
// Layout: an arch check that kills the process on a foreign ABI (the
// syscall numbers would not match the table), load syscall nr, on amd64 a
// kill for x32 numbers, [1..n] JEQ per syscall jumping to RET USER_NOTIF,
// then RET ALLOW, RET USER_NOTIF. The JEQ for syscall i therefore jumps n-i
// instructions forward.
func landlockBuildNotifyFilter(syscalls ...uint32) *unix.SockFprog {
	var filter []unix.SockFilter
	if seccompNativeArch != 0 {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataArchOffset},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: seccompNativeArch},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompDataNrOffset})
	if seccompX32SyscallBit != 0 {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: seccompX32SyscallBit},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	for i, sc := range syscalls {
		filter = append(filter, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			Jt:   uint8(len(syscalls) - i),
			K:    sc,
		})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF})

	return &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
}

// landlockNotifySyscalls computes the syscall set the seccomp filter traps
// for the given policy. execve/execveat are always trapped (deny-exec
// enforcement); the path syscalls (seccompPathSyscalls) only when fs deny
// rules exist; connect/sendto/sendmsg (and io_uring_setup — see
// handleIoUringSetup) only under network lockdown. sendmsg covers Go's
// WriteMsgUDP datagrams; sendmmsg batched destinations are a documented gap
// (see docs/sandbox-landlock.md).
func landlockNotifySyscalls(network landlockNetworkPolicy, interceptPaths bool) []uint32 {
	syscalls := []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT)}
	if interceptPaths {
		syscalls = append(syscalls, pathSyscallNumbers()...)
	}
	if network.Lockdown {
		syscalls = append(syscalls,
			uint32(unix.SYS_CONNECT), uint32(unix.SYS_SENDTO), uint32(unix.SYS_SENDMSG),
			uint32(unix.SYS_IO_URING_SETUP))
	}
	return syscalls
}

// matchDeniedPath returns the deny entry that denies opening path with the
// given flags, if any. flags uses O_ACCMODE constants (O_RDONLY, O_WRONLY,
// O_RDWR). Matching rules:
//   - Exact match: /home/user/.env matches deny /home/user/.env
//   - Directory subtree: /home/user/.ssh/id_rsa matches deny /home/user/.ssh
//     or deny /home/user/.ssh/ (either with or without trailing slash — a
//     deny entry without slash is treated as "this path OR anything beneath it")
//   - Must NOT match partial names: /home/.envrc does NOT match deny /home/.env
func matchDeniedPath(path string, flags int, denyPaths []denyPathEntry) (denyPathEntry, bool) {
	accessMode := flags & unix.O_ACCMODE

	for _, entry := range denyPaths {
		if !pathCoveredBy(path, entry) {
			continue
		}
		switch entry.Mode {
		case denyRead:
			if accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR {
				return entry, true
			}
		case denyWrite:
			if accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR {
				return entry, true
			}
		case denyBoth:
			return entry, true
		}
	}

	return denyPathEntry{}, false
}

// isPathDenied reports whether matchDeniedPath finds a deny entry for path.
func isPathDenied(path string, flags int, denyPaths []denyPathEntry) bool {
	_, denied := matchDeniedPath(path, flags, denyPaths)
	return denied
}

// matchDeniedExec returns the deny exec entry matching path, if any.
// Same matching rules as matchDeniedPath but no flag check.
func matchDeniedExec(path string, denyExec []string) (string, bool) {
	for _, entry := range denyExec {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(path, entry) {
				return entry, true
			}
		} else {
			if path == entry || strings.HasPrefix(path, entry+"/") {
				return entry, true
			}
		}
	}

	return "", false
}

// isExecDenied reports whether matchDeniedExec finds a deny entry for path.
func isExecDenied(path string, denyExec []string) bool {
	_, denied := matchDeniedExec(path, denyExec)
	return denied
}

// readPathFromMem reads a null-terminated path string from a process's memory
// via a pre-opened /proc/<pid>/mem file descriptor. Uses ReadAt (pread syscall)
// which is NOT intercepted by the seccomp filter. Max 4096 bytes.
func readPathFromMem(memFd *os.File, addr uintptr) (string, error) {
	buf := make([]byte, 4096)

	n, err := memFd.ReadAt(buf, int64(addr))
	if err != nil && n == 0 {
		return "", fmt.Errorf("read process memory at 0x%x: %w", addr, err)
	}

	// Find the null terminator.
	idx := 0
	for idx < n {
		if buf[idx] == 0 {
			break
		}
		idx++
	}

	// An empty path is valid with AT_EMPTY_PATH: the dirfd is the target.
	return string(buf[:idx]), nil
}

// _AT_FDCWD is the Linux AT_FDCWD constant (-100). When stored as uint64 in
// seccomp args it may appear as 0xFFFFFF9C (32-bit sign-extended) or
// 0xFFFFFFFFFFFFFF9C (64-bit).
const (
	_AT_FDCWD_32 = 0xFFFFFF9C
	_AT_FDCWD_64 = 0xFFFFFFFFFFFFFF9C
)

// dirfdFromArgs extracts the dirfd from seccomp args, handling AT_FDCWD
// sign-extension from uint64.
func dirfdFromArgs(val uint64) int {
	if val == _AT_FDCWD_32 || val == _AT_FDCWD_64 {
		return -100
	}
	return int(int32(val))
}

// seccompPhase holds the enforcement state for the seccomp supervisor.
type seccompPhase struct {
	enforcing   bool
	childPID    uint32
	denyPaths   []denyPathEntry
	denyExec    []string
	network     landlockNetworkPolicy
	auditWriter io.Writer
}

// seccompSupervisor manages the seccomp notification loop.
type seccompSupervisor struct {
	notifyFd int
	// stopFd is an eventfd written to by Stop() to wake the recv loop.
	// Closing notifyFd does NOT wake a goroutine blocked in ioctl(NOTIF_RECV),
	// so we poll on both fds and use stopFd as an interrupt.
	stopFd int
	phase  atomic.Pointer[seccompPhase]
	// enforceReady is closed by Enforce once the enforcement phase is stored.
	// The loop holds every notification behind this gate so the shim's setup
	// syscalls and any early target connect stay trapped in the kernel until
	// lockdown is actually installed — closing the startup race.
	enforceReady chan struct{}
	// stopCh is closed by Stop to release the loop if it is still waiting on
	// enforceReady (e.g. an error path aborts before Enforce is ever called).
	stopCh   chan struct{}
	stopOnce sync.Once
	loopDone chan struct{}
}

// newLandlockSupervisorFromFd wraps an already-created seccomp notify fd
// (obtained from the shim over a socketpair) in a supervisor. It does NOT
// install a filter — the shim did that inside its user namespace so the
// helper stays unfiltered.
func newLandlockSupervisorFromFd(notifyFd int) (*seccompSupervisor, error) {
	stopFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(notifyFd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	s := &seccompSupervisor{
		notifyFd:     notifyFd,
		stopFd:       stopFd,
		enforceReady: make(chan struct{}),
		stopCh:       make(chan struct{}),
		loopDone:     make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// Enforce transitions the supervisor to enforcement mode. From this point on,
// syscalls from childPID and its descendants are checked against the deny lists
// and the network lockdown config.
func (s *seccompSupervisor) Enforce(childPID int, denyPaths []denyPathEntry, denyExec []string, network landlockNetworkPolicy, auditWriter io.Writer) error {
	p := &seccompPhase{
		enforcing:   true,
		childPID:    uint32(childPID),
		denyPaths:   resolveDenyEntries(uint32(childPID), denyPaths),
		denyExec:    resolveDenyExec(uint32(childPID), denyExec),
		network:     network,
		auditWriter: auditWriter,
	}
	s.phase.Store(p)
	close(s.enforceReady)
	return nil
}

// memFdFor opens a fresh /proc/<pid>/mem fd for the given PID. The caller
// must close it. No caching: an open fd pins the task's mm at open() time,
// so a cached fd silently reads a dead address space once the task execve's
// (or its tid is recycled). A notifying thread is parked in the kernel and
// cannot execve until answered, and execve kills all sibling threads, so a
// fresh open here always pins the live mm.
func (p *seccompPhase) memFdFor(pid uint32) *os.File {
	fd, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil
	}
	return fd
}

// closeMemFd closes a per-notification mem fd, logging close failures instead
// of discarding them.
func closeMemFd(fd *os.File) {
	if err := fd.Close(); err != nil {
		log.Warnf("close /proc/pid/mem: %v", err)
	}
}

// Stop signals the recv loop to exit via the eventfd, waits for it, then
// closes the notification fd. Closing notifyFd alone does NOT wake a
// goroutine blocked in ioctl(SECCOMP_IOCTL_NOTIF_RECV).
func (s *seccompSupervisor) Stop() error {
	s.stopOnce.Do(func() { close(s.stopCh) })
	var one = [8]byte{1}
	_, _ = unix.Write(s.stopFd, one[:])
	<-s.loopDone
	if err := unix.Close(s.notifyFd); err != nil {
		log.Warnf("close seccomp notify fd: %v", err)
	}
	if err := unix.Close(s.stopFd); err != nil {
		log.Warnf("close seccomp stop fd: %v", err)
	}
	return nil
}

// loop is the main notification processing goroutine.
func (s *seccompSupervisor) loop() {
	defer close(s.loopDone)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Do not touch a single notification until Enforce installs the phase.
	// Trapped syscalls stay queued in the kernel until then, so a fast target
	// cannot slip a connect/exec past lockdown while the helper is still
	// opening /proc/<pid>/mem.
	select {
	case <-s.enforceReady:
	case <-s.stopCh:
		return
	}

	for {
		ready, err := waitForNotif(s.notifyFd, s.stopFd)
		if err != nil || !ready {
			// stop signalled or fatal poll error — exit loop.
			return
		}
		notif, err := recvNotification(s.notifyFd)
		if err != nil {
			// ENOENT: notif expired (process exited between poll and recv).
			// Retry the loop rather than exit — the listener is still valid.
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return
		}

		phase := s.phase.Load()
		if phase == nil || !phase.enforcing {
			s.continueSyscall(notif.ID)
			continue
		}

		// Enforce for the direct child AND all descendants. A memfd per
		// notifying PID is resolved lazily in handlePathOp/handleExec — we do
		// NOT skip descendants here, because npm-style flows spawn real work
		// (node, python, etc.) as grandchildren and the deny list must apply
		// to them too.

		switch notif.Data.Nr {
		case int32(unix.SYS_EXECVE), int32(unix.SYS_EXECVEAT):
			s.handleExec(notif, phase)
		case int32(unix.SYS_CONNECT), int32(unix.SYS_SENDTO), int32(unix.SYS_SENDMSG):
			s.handleConnect(notif, phase)
		case int32(unix.SYS_IO_URING_SETUP):
			s.handleIoUringSetup(notif, phase)
		default:
			if op, ok := seccompPathSyscalls[uint32(notif.Data.Nr)]; ok {
				s.handlePathOp(notif, phase, op)
				continue
			}
			s.continueSyscall(notif.ID)
		}
	}
}

func (s *seccompSupervisor) handleExec(notif *seccompNotification, phase *seccompPhase) {
	// For execve: args[0] is filename pointer.
	// For execveat: args[0] is dirfd, args[1] is filename pointer.
	var pathAddr uintptr
	var dirfd int

	if notif.Data.Nr == int32(unix.SYS_EXECVE) {
		pathAddr = uintptr(notif.Data.Args[0])
		dirfd = -100 // AT_FDCWD
	} else {
		dirfd = dirfdFromArgs(notif.Data.Args[0])
		pathAddr = uintptr(notif.Data.Args[1])
	}

	memFd := phase.memFdFor(notif.PID)
	if memFd == nil {
		// Process gone or /proc/<pid>/mem unreadable — fail-closed would
		// kill the process; fail-open to avoid breaking legit flows.
		s.continueSyscall(notif.ID)
		return
	}
	defer closeMemFd(memFd)

	rawPath, err := readPathFromMem(memFd, pathAddr)
	if err != nil {
		// Cannot read memory (EIO, ESRCH) — process may have died. Continue.
		s.continueSyscall(notif.ID)
		return
	}

	resolved, err := resolveNotifPath(notif.PID, dirfd, rawPath, true)
	if err != nil {
		s.continueSyscall(notif.ID)
		return
	}

	if rule, denied := matchDeniedExec(resolved, phase.denyExec); denied {
		if phase.auditWriter != nil {
			if err := landlockWriteAuditEvent(phase.auditWriter, auditEvent{
				Type:     auditSeccompDeny,
				Syscall:  syscallName(notif.Data.Nr),
				Path:     resolved,
				RulePath: rule,
				Comm:     procComm(notif.PID),
				PID:      int(notif.PID),
				Ts:       time.Now().UnixNano(),
			}); err != nil {
				log.Warnf("sandbox: failed to record a denial: %v", err)
			}
		}
		traceSeccompDecision("deny %s pid=%d path=%s rule=%s", syscallName(notif.Data.Nr), notif.PID, resolved, rule)
		s.deny(notif.ID)
		return
	}

	traceSeccompDecision("allow %s pid=%d path=%s", syscallName(notif.Data.Nr), notif.PID, resolved)
	s.continueSyscall(notif.ID)
}

// handleIoUringSetup denies io_uring_setup under network lockdown. A ring is a
// side channel for IORING_OP_CONNECT/SENDMSG that never traps the intercepted
// network syscalls; refusing ring creation (EPERM) forces callers back onto
// the confined path. The target is freshly execve'd after filter install, so
// it holds no ring created before enforcement.
func (s *seccompSupervisor) handleIoUringSetup(notif *seccompNotification, phase *seccompPhase) {
	if !phase.network.Lockdown {
		s.continueSyscall(notif.ID)
		return
	}
	if phase.auditWriter != nil {
		if err := landlockWriteAuditEvent(phase.auditWriter, auditEvent{
			Type:    auditNetworkDeny,
			Syscall: syscallName(notif.Data.Nr),
			Message: "io_uring_setup denied under network_via_proxy_only",
			Comm:    procComm(notif.PID),
			PID:     int(notif.PID),
			Ts:      time.Now().UnixNano(),
		}); err != nil {
			log.Warnf("sandbox: failed to record a denial: %v", err)
		}
	}
	traceSeccompDecision("deny %s pid=%d reason=io_uring_setup denied under network_via_proxy_only", syscallName(notif.Data.Nr), notif.PID)
	if err := respondErrno(s.notifyFd, notif.ID, unix.EPERM); err != nil {
		log.Warnf("seccomp io_uring_setup deny for notif %d failed: %v", notif.ID, err)
	}
}

// dnsPort is the well-known DNS port re-opened under allow_direct_dns.
const dnsPort = 53

// allowOutbound reports whether an outbound connection to addr:port is
// permitted under the network confinement config. Matches the Seatbelt
// network_via_proxy_only semantics: loopback traffic reaches the PMG proxy
// port (and any loopback port when the profile also allows network bind, so
// dev servers keep working); direct DNS to port 53 only when the profile
// opts in; everything else non-loopback is denied.
//
// Non-INET families are allow-listed, not blanket-allowed: AF_UNIX and
// AF_NETLINK carry no external egress (local IPC / kernel interfaces) and are
// needed by systemd-resolved and getaddrinfo interface enumeration. Every
// other family is denied — notably AF_VSOCK, which in a VM reaches host/guest
// services entirely outside the proxy. AF_UNIX resolver access is a documented
// gap in docs/sandbox-landlock.md.
func (n landlockNetworkPolicy) allowOutbound(family uint16, addr netip.Addr, port uint16) bool {
	if !n.Lockdown {
		return true
	}

	switch family {
	case unix.AF_INET, unix.AF_INET6:
		if addr.IsLoopback() {
			return port == n.ProxyPort || n.AllowBind || (n.AllowDirectDNS && port == dnsPort)
		}
		return n.AllowDirectDNS && port == dnsPort
	case unix.AF_UNIX, unix.AF_NETLINK:
		return true
	default:
		return false
	}
}

// netPeer is a parsed outbound destination from a sockaddr.
type netPeer struct {
	family uint16
	addr   netip.Addr
	port   uint16
}

func (p netPeer) String() string {
	if !p.addr.IsValid() {
		return fmt.Sprintf("family:%d", p.family)
	}
	return netip.AddrPortFrom(p.addr, p.port).String()
}

var errShortSockaddr = errors.New("sockaddr too short for family")

// readNetPeer reads and parses a sockaddr from the trapping process's memory
// via /proc/<pid>/mem. addrPtr/addrLen are the userspace pointer and length
// syscall arguments. Only the family is parsed for non-INET sockets; callers
// decide on family alone for those.
func readNetPeer(memFd *os.File, addrPtr, addrLen uint64) (netPeer, error) {
	var famBuf [2]byte
	if _, err := memFd.ReadAt(famBuf[:], int64(addrPtr)); err != nil {
		return netPeer{}, fmt.Errorf("read sockaddr family: %w", err)
	}

	peer := netPeer{family: binary.NativeEndian.Uint16(famBuf[:])}

	switch peer.family {
	case unix.AF_INET:
		if addrLen < 16 {
			return peer, fmt.Errorf("%w: AF_INET needs 16, got %d", errShortSockaddr, addrLen)
		}
		buf := make([]byte, 16)
		if _, err := memFd.ReadAt(buf, int64(addrPtr)); err != nil {
			return peer, fmt.Errorf("read sockaddr_in: %w", err)
		}
		peer.port = binary.BigEndian.Uint16(buf[2:4])
		peer.addr = netip.AddrFrom4([4]byte{buf[4], buf[5], buf[6], buf[7]})
	case unix.AF_INET6:
		if addrLen < 28 {
			return peer, fmt.Errorf("%w: AF_INET6 needs 28, got %d", errShortSockaddr, addrLen)
		}
		buf := make([]byte, 28)
		if _, err := memFd.ReadAt(buf, int64(addrPtr)); err != nil {
			return peer, fmt.Errorf("read sockaddr_in6: %w", err)
		}
		peer.port = binary.BigEndian.Uint16(buf[2:4])
		var addr [16]byte
		copy(addr[:], buf[8:24])
		// Unmap normalizes v4-mapped v6 (::ffff:127.0.0.1) so the loopback
		// check below treats dual-stack clients like plain IPv4.
		peer.addr = netip.AddrFrom16(addr).Unmap()
	default:
		// Non-INET family: family-only decision in allowOutbound.
	}

	return peer, nil
}

// seccompTracing gates decision-level tracing of the notify supervisor,
// enabled via PMG_SECCOMP_TRACE=1 (or true/on/yes). Traces go through the
// helper's logger (APP_LOG_FILE / APP_LOG_LEVEL control destination and
// verbosity). Use it to debug sandbox enforcement: every intercepted
// syscall's allow/deny decision is logged with its target and reason.
var seccompTracing = func() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PMG_SECCOMP_TRACE"))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}()

func traceSeccompDecision(format string, args ...any) {
	if seccompTracing {
		log.Debugf("seccomp: "+format, args...)
	}
}

// handleConnect enforces network_via_proxy_only for connect(2), sendto(2),
// and sendmsg(2). sendto/sendmsg with a NULL destination target the socket's
// already-connected peer — that peer passed the connect check, so they
// continue uninspected.
//
// Unlike handleOpen, an unreadable sockaddr is NOT fail-open: under lockdown
// an unverifiable destination is indistinguishable from a hostile one (e.g.
// dumpable=0 after a hostile execve), so we deny and audit instead.
func (s *seccompSupervisor) handleConnect(notif *seccompNotification, phase *seccompPhase) {
	if !phase.network.Lockdown {
		s.continueSyscall(notif.ID)
		return
	}

	// Open process memory lazily: a NULL-destination sendto/sendmsg on a
	// connected socket targets an already-validated peer, so it must
	// continue uninspected without ever requiring a mem fd.
	var memFd *os.File
	openMem := func() *os.File {
		if memFd == nil {
			memFd = phase.memFdFor(notif.PID)
		}
		return memFd
	}
	defer func() {
		if memFd != nil {
			closeMemFd(memFd)
		}
	}()

	addrPtr, addrLen, hasDest, ok := netSockaddrAddr(notif, openMem)
	if !ok {
		traceSeccompDecision("deny %s pid=%d: could not resolve destination address", syscallName(notif.Data.Nr), notif.PID)
		s.denyNetworkConnect(notif, phase, "", "could not resolve destination address")
		return
	}
	if !hasDest {
		s.continueSyscall(notif.ID)
		return
	}
	if openMem() == nil {
		traceSeccompDecision("deny %s pid=%d: unreadable process memory", syscallName(notif.Data.Nr), notif.PID)
		s.denyNetworkConnect(notif, phase, "", "unreadable process memory")
		return
	}

	peer, err := readNetPeer(memFd, addrPtr, addrLen)
	if err != nil {
		traceSeccompDecision("deny %s pid=%d endpoint=read-failed reason=%q", syscallName(notif.Data.Nr), notif.PID, err)
		s.denyNetworkConnect(notif, phase, "", err.Error())
		return
	}

	if phase.network.allowOutbound(peer.family, peer.addr, peer.port) {
		traceSeccompDecision("allow %s pid=%d peer=%s", syscallName(notif.Data.Nr), notif.PID, peer)
		s.continueSyscall(notif.ID)
		return
	}

	traceSeccompDecision("deny %s pid=%d peer=%s reason=network_via_proxy_only", syscallName(notif.Data.Nr), notif.PID, peer)
	s.denyNetworkConnect(notif, phase, peer.String(), "network_via_proxy_only")
}

// netSockaddrAddr extracts the destination sockaddr pointer and length from
// the intercepted syscall's arguments. hasDest is false when the syscall
// carries no destination (sendto/sendmsg on a connected socket), in which
// case the caller continues without a policy decision. openMem is invoked at
// most once, only when the destination must be chased through process memory
// (sendmsg's msghdr); connect and sendto expose their sockaddr in args.
func netSockaddrAddr(notif *seccompNotification, openMem func() *os.File) (addrPtr, addrLen uint64, hasDest, ok bool) {
	switch notif.Data.Nr {
	case int32(unix.SYS_CONNECT):
		ptr, length := notif.Data.Args[1], notif.Data.Args[2]
		return ptr, length, ptr != 0 && length > 0, true

	case int32(unix.SYS_SENDTO):
		ptr, length := notif.Data.Args[4], notif.Data.Args[5]
		if ptr == 0 {
			return 0, 0, false, true
		}
		return ptr, length, true, true

	case int32(unix.SYS_SENDMSG):
		// struct msghdr { void *msg_name; socklen_t msg_namelen; ... }:
		// name pointer at offset 0, namelen (u32) at offset 8.
		memFd := openMem()
		if memFd == nil {
			return 0, 0, false, false
		}
		var hdr [16]byte
		if _, err := memFd.ReadAt(hdr[:], int64(notif.Data.Args[1])); err != nil {
			return 0, 0, false, false
		}
		ptr := binary.NativeEndian.Uint64(hdr[0:8])
		length := uint64(binary.NativeEndian.Uint32(hdr[8:12]))
		if ptr == 0 {
			return 0, 0, false, true
		}
		return ptr, length, true, true
	}

	return 0, 0, false, false
}

// denyNetworkConnect fails the intercepted network syscall and emits an
// audit event. Errors are surfaced as ECONNREFUSED so tools report the
// familiar "connection refused" rather than a filesystem-flavored EACCES.
func (s *seccompSupervisor) denyNetworkConnect(notif *seccompNotification, phase *seccompPhase, target, message string) {
	if phase.auditWriter != nil {
		if err := landlockWriteAuditEvent(phase.auditWriter, auditEvent{
			Type:    auditNetworkDeny,
			Syscall: syscallName(notif.Data.Nr),
			Path:    target,
			Message: message,
			Comm:    procComm(notif.PID),
			PID:     int(notif.PID),
			Ts:      time.Now().UnixNano(),
		}); err != nil {
			log.Warnf("sandbox: failed to record a denial: %v", err)
		}
	}
	s.denyConnRefused(notif.ID)
}

// syscallName returns a human-readable name for known intercepted syscalls.
func syscallName(nr int32) string {
	if op, ok := seccompPathSyscalls[uint32(nr)]; ok {
		return op.name
	}
	switch nr {
	case int32(unix.SYS_EXECVE):
		return "execve"
	case int32(unix.SYS_EXECVEAT):
		return "execveat"
	case int32(unix.SYS_CONNECT):
		return "connect"
	case int32(unix.SYS_SENDTO):
		return "sendto"
	case int32(unix.SYS_SENDMSG):
		return "sendmsg"
	case int32(unix.SYS_IO_URING_SETUP):
		return "io_uring_setup"
	default:
		return fmt.Sprintf("syscall_%d", nr)
	}
}

// accessModeString maps an O_ACCMODE value to the audit event access label.
// O_RDWR counts as write: the denial applies to the stronger access.
func accessModeString(flags int) string {
	if flags&unix.O_ACCMODE == unix.O_RDONLY {
		return "read"
	}
	return "write"
}

// denyAccessLabel reports the direction of the deny rule that fired, not the
// requested access. An O_RDWR open denied by a read-only rule must surface as
// a read denial: the write override prunes only deny_write entries, so only a
// read allowance unblocks it. denyBoth falls back to the requested access.
func denyAccessLabel(mode denyMode, flags int) string {
	switch mode {
	case denyRead:
		return "read"
	case denyWrite:
		return "write"
	default:
		return accessModeString(flags)
	}
}

// procComm returns the process name from /proc/<pid>/comm, best-effort. The
// process may already be gone when the denial is recorded, so failures yield
// an empty name rather than an error.
func procComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// waitForNotif blocks until notifyFd has a notification to read or stopFd is
// signalled. Returns (true, nil) when a notification is ready, (false, nil)
// when stop was signalled, and (false, err) on fatal errors.
func waitForNotif(notifyFd, stopFd int) (bool, error) {
	pfds := []unix.PollFd{
		{Fd: int32(notifyFd), Events: unix.POLLIN},
		{Fd: int32(stopFd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Ppoll(pfds, nil, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("ppoll: %w", err)
		}
		if pfds[1].Revents&unix.POLLIN != 0 {
			return false, nil
		}
		if pfds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0 {
			// POLLERR/POLLHUP on notifyFd means the child died and the
			// listener is no longer useful — caller will see EINVAL on recv.
			return true, nil
		}
	}
}

// recvNotification receives a seccomp notification from the notification fd.
// Retries on EINTR which can happen due to Go runtime signals.
func recvNotification(fd int) (*seccompNotification, error) {
	var notif seccompNotification

	for {
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			_SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&notif)),
		)
		if errno == 0 {
			return &notif, nil
		}
		if errno == unix.EINTR {
			continue
		}
		return nil, fmt.Errorf("ioctl SECCOMP_IOCTL_NOTIF_RECV: %w", errno)
	}
}

// A failed SEND means the notification could not be answered (typically the
// process already exited) — logged rather than dropped so it stays visible.
func (s *seccompSupervisor) continueSyscall(id uint64) {
	if err := respondContinue(s.notifyFd, id); err != nil {
		log.Warnf("seccomp continue for notif %d failed: %v", id, err)
	}
}

func (s *seccompSupervisor) deny(id uint64) {
	if err := respondDeny(s.notifyFd, id); err != nil {
		log.Warnf("seccomp deny for notif %d failed: %v", id, err)
	}
}

func (s *seccompSupervisor) denyConnRefused(id uint64) {
	if err := respondDenyConnRefused(s.notifyFd, id); err != nil {
		log.Warnf("seccomp network deny for notif %d failed: %v", id, err)
	}
}

// respondContinue tells the kernel to continue the syscall as if the filter
// was not installed (SECCOMP_USER_NOTIF_FLAG_CONTINUE).
func respondContinue(fd int, id uint64) error {
	resp := seccompNotifResp{
		ID:    id,
		Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
	}

	for {
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			_SECCOMP_IOCTL_NOTIF_SEND,
			uintptr(unsafe.Pointer(&resp)),
		)
		if errno == 0 {
			return nil
		}
		if errno == unix.EINTR {
			continue
		}
		return fmt.Errorf("ioctl SECCOMP_IOCTL_NOTIF_SEND (continue): %w", errno)
	}
}

// respondDeny tells the kernel to fail the syscall with EACCES.
func respondDeny(fd int, id uint64) error {
	return respondErrno(fd, id, unix.EACCES)
}

// respondDenyConnRefused tells the kernel to fail the syscall with
// ECONNREFUSED — the familiar net-stack error for network denials.
func respondDenyConnRefused(fd int, id uint64) error {
	return respondErrno(fd, id, unix.ECONNREFUSED)
}

func respondErrno(fd int, id uint64, errno unix.Errno) error {
	resp := seccompNotifResp{
		ID:    id,
		Error: -int32(errno),
	}

	for {
		_, _, sysErrno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			_SECCOMP_IOCTL_NOTIF_SEND,
			uintptr(unsafe.Pointer(&resp)),
		)
		if sysErrno == 0 {
			return nil
		}
		if sysErrno == unix.EINTR {
			continue
		}
		return fmt.Errorf("ioctl SECCOMP_IOCTL_NOTIF_SEND (deny): %w", sysErrno)
	}
}
