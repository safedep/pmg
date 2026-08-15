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
	"path/filepath"
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

// landlockBuildNotifyFilter builds a classic BPF program returning
// SECCOMP_RET_USER_NOTIF for the given syscalls and SECCOMP_RET_ALLOW for
// everything else. Shared by the shim (which installs it inside the user
// namespace without NNP) and tests.
//
// Layout: [0] load syscall nr, [1..n] JEQ per syscall jumping to RET
// USER_NOTIF, [n+1] RET ALLOW, [n+2] RET USER_NOTIF. The JEQ at index 1+i
// therefore jumps (n+2)-(1+i)-1 = n-i instructions forward.
func landlockBuildNotifyFilter(syscalls ...uint32) *unix.SockFprog {
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
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
// enforcement); openat/openat2 only when fs deny rules exist;
// connect/sendto/sendmsg only under network lockdown. sendmsg covers Go's
// WriteMsgUDP datagrams; sendmmsg batched destinations are a documented gap
// (see docs/sandbox-landlock.md).
func landlockNotifySyscalls(network landlockNetworkPolicy, interceptOpen bool) []uint32 {
	syscalls := []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT)}
	if interceptOpen {
		syscalls = append(syscalls, uint32(unix.SYS_OPENAT), uint32(unix.SYS_OPENAT2))
	}
	if network.Lockdown {
		syscalls = append(syscalls, uint32(unix.SYS_CONNECT), uint32(unix.SYS_SENDTO), uint32(unix.SYS_SENDMSG))
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
		matched := false
		if strings.HasSuffix(entry.Path, "/") {
			// Directory prefix match: path must start with the deny prefix.
			matched = strings.HasPrefix(path, entry.Path)
		} else {
			// Exact match OR any path under this entry as a directory.
			matched = path == entry.Path || strings.HasPrefix(path, entry.Path+"/")
		}

		if !matched {
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

	if idx == 0 {
		return "", fmt.Errorf("empty path at 0x%x", addr)
	}

	return string(buf[:idx]), nil
}

// _AT_FDCWD is the Linux AT_FDCWD constant (-100). When stored as uint64 in
// seccomp args it may appear as 0xFFFFFF9C (32-bit sign-extended) or
// 0xFFFFFFFFFFFFFF9C (64-bit).
const (
	_AT_FDCWD_32 = 0xFFFFFF9C
	_AT_FDCWD_64 = 0xFFFFFFFFFFFFFF9C
)

// resolveNotifPath resolves a path from seccomp notification arguments.
// Handles AT_FDCWD and dirfd-relative paths via os.Readlink on /proc/<pid>/cwd
// and /proc/<pid>/fd/<dirfd>. readlinkat syscall is NOT intercepted.
func resolveNotifPath(pid uint32, dirfd int, rawPath string) (string, error) {
	// Absolute path: return as-is.
	if filepath.IsAbs(rawPath) {
		return filepath.Clean(rawPath), nil
	}

	var base string

	// Check for AT_FDCWD (which is -100, but may be sign-extended in uint64).
	if dirfd == -100 {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return "", fmt.Errorf("readlink /proc/%d/cwd: %w", pid, err)
		}
		base = cwd
	} else {
		fdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
		if err != nil {
			return "", fmt.Errorf("readlink /proc/%d/fd/%d: %w", pid, dirfd, err)
		}
		base = fdPath
	}

	return filepath.Clean(filepath.Join(base, rawPath)), nil
}

// classifyOpenFlags extracts O_ACCMODE from openat flags.
// For openat(2): flags are in args[2] directly.
// For openat2(2): args[2] is a pointer to an open_how struct where the first
// uint64 field is the flags. We read those from process memory.
func classifyOpenFlags(nr int32, args [6]uint64, memFd *os.File) int {
	if nr == int32(unix.SYS_OPENAT) {
		return int(args[2]) & unix.O_ACCMODE
	}

	// openat2: args[2] is a pointer to struct open_how { u64 flags; u64 mode; u64 resolve; }
	if nr == int32(unix.SYS_OPENAT2) && memFd != nil {
		buf := make([]byte, 8)
		_, err := memFd.ReadAt(buf, int64(args[2]))
		if err != nil {
			// Cannot read open_how struct; default to read-only (conservative).
			return unix.O_RDONLY
		}
		flags := binary.LittleEndian.Uint64(buf)
		return int(flags) & unix.O_ACCMODE
	}

	return unix.O_RDONLY
}

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
	enforcing bool
	childPID  uint32
	// memFd is the pre-opened /proc/<childPID>/mem fd for the direct child.
	// Descendants (grandchildren spawned via fork/exec) have their own PIDs;
	// use memFdFor(pid) to resolve the right fd for any notification.
	memFd       *os.File
	denyPaths   []denyPathEntry
	denyExec    []string
	network     landlockNetworkPolicy
	auditWriter io.Writer

	// memFdCache maps descendant PID -> /proc/<pid>/mem fd. Entries live for
	// the duration of the enforce phase; fds are closed in (*seccompSupervisor).Stop.
	memFdMu    sync.Mutex
	memFdCache map[uint32]*os.File
}

// seccompSupervisor manages the seccomp notification loop.
type seccompSupervisor struct {
	notifyFd int
	// stopFd is an eventfd written to by Stop() to wake the recv loop.
	// Closing notifyFd does NOT wake a goroutine blocked in ioctl(NOTIF_RECV),
	// so we poll on both fds and use stopFd as an interrupt.
	stopFd   int
	phase    atomic.Pointer[seccompPhase]
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
		notifyFd: notifyFd,
		stopFd:   stopFd,
		loopDone: make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// Enforce transitions the supervisor to enforcement mode. From this point on,
// syscalls from childPID and its descendants are checked against the deny lists
// and the network lockdown config.
func (s *seccompSupervisor) Enforce(childPID int, memFd *os.File, denyPaths []denyPathEntry, denyExec []string, network landlockNetworkPolicy, auditWriter io.Writer) error {
	p := &seccompPhase{
		enforcing:   true,
		childPID:    uint32(childPID),
		memFd:       memFd,
		denyPaths:   denyPaths,
		denyExec:    denyExec,
		network:     network,
		auditWriter: auditWriter,
		memFdCache:  map[uint32]*os.File{uint32(childPID): memFd},
	}
	s.phase.Store(p)
	return nil
}

// memFdFor returns an open /proc/<pid>/mem fd for the given PID, caching it.
// Returns nil if the fd cannot be opened (e.g., dumpable=0 from an execve
// inside the sandboxed process tree, or the process already exited).
func (p *seccompPhase) memFdFor(pid uint32) *os.File {
	p.memFdMu.Lock()
	defer p.memFdMu.Unlock()
	if fd, ok := p.memFdCache[pid]; ok {
		return fd
	}
	fd, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil
	}
	p.memFdCache[pid] = fd
	return fd
}

// invalidateMemFd drops the cached /proc/<pid>/mem fd. Call this after an
// execve on `pid`: execve can change the process's address space layout and
// (crucially) its dumpable / PTRACE_MODE_ATTACH state, which invalidates
// reads through the existing mem fd with EIO/EOF. Callers will reopen on
// the next lookup.
func (p *seccompPhase) invalidateMemFd(pid uint32) {
	p.memFdMu.Lock()
	defer p.memFdMu.Unlock()
	if fd, ok := p.memFdCache[pid]; ok {
		_ = fd.Close()
		delete(p.memFdCache, pid)
	}
}

// closeDescendantMemFds closes all cached memfd entries EXCEPT the direct
// child's. Called on Stop; the direct child's memfd is owned by the helper
// caller and closed separately.
func (p *seccompPhase) closeDescendantMemFds() {
	p.memFdMu.Lock()
	defer p.memFdMu.Unlock()
	for pid, fd := range p.memFdCache {
		if pid == p.childPID {
			continue
		}
		_ = fd.Close()
		delete(p.memFdCache, pid)
	}
}

// Stop signals the recv loop to exit via the eventfd, waits for it, then
// closes the notification fd. Closing notifyFd alone does NOT wake a
// goroutine blocked in ioctl(SECCOMP_IOCTL_NOTIF_RECV).
func (s *seccompSupervisor) Stop() error {
	var one = [8]byte{1}
	_, _ = unix.Write(s.stopFd, one[:])
	<-s.loopDone
	if phase := s.phase.Load(); phase != nil {
		phase.closeDescendantMemFds()
	}
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
			_ = respondContinue(s.notifyFd, notif.ID)
			continue
		}

		// Enforce for the direct child AND all descendants. A memfd per
		// notifying PID is resolved lazily in handleOpen/handleExec — we do
		// NOT skip descendants here, because npm-style flows spawn real work
		// (node, python, etc.) as grandchildren and the deny list must apply
		// to them too.

		switch notif.Data.Nr {
		case int32(unix.SYS_EXECVE), int32(unix.SYS_EXECVEAT):
			s.handleExec(notif, phase)
			// execve reshapes the process's memory layout and may drop
			// PTRACE-read permission (if the new binary is setuid or
			// changes dumpable). Drop the cached memfd so the next
			// openat re-opens /proc/<pid>/mem fresh.
			phase.invalidateMemFd(notif.PID)
		case int32(unix.SYS_OPENAT), int32(unix.SYS_OPENAT2):
			s.handleOpen(notif, phase)
		case int32(unix.SYS_CONNECT), int32(unix.SYS_SENDTO), int32(unix.SYS_SENDMSG):
			s.handleConnect(notif, phase)
		default:
			_ = respondContinue(s.notifyFd, notif.ID)
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
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	rawPath, err := readPathFromMem(memFd, pathAddr)
	if err != nil {
		// Cannot read memory (EIO, ESRCH) — process may have died. Continue.
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	resolved, err := resolveNotifPath(notif.PID, dirfd, rawPath)
	if err != nil {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	if rule, denied := matchDeniedExec(resolved, phase.denyExec); denied {
		if phase.auditWriter != nil {
			_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
				Type:     auditSeccompDeny,
				Syscall:  syscallName(notif.Data.Nr),
				Path:     resolved,
				RulePath: rule,
				Comm:     procComm(notif.PID),
				PID:      int(notif.PID),
				Ts:       time.Now().UnixNano(),
			})
		}
		_ = respondDeny(s.notifyFd, notif.ID)
		return
	}

	_ = respondContinue(s.notifyFd, notif.ID)
}

func (s *seccompSupervisor) handleOpen(notif *seccompNotification, phase *seccompPhase) {
	dirfd := dirfdFromArgs(notif.Data.Args[0])
	pathAddr := uintptr(notif.Data.Args[1])

	memFd := phase.memFdFor(notif.PID)
	if memFd == nil {
		// Can't read the target's memory — typically because an execve in the
		// process chain with NO_NEW_PRIVS set makes /proc/<pid>/mem owner-RW
		// only via CAP_SYS_PTRACE (dumpable=0). Fail open rather than deny
		// every openat from the process, but this is a real enforcement gap
		// for grandchild processes. See docs/sandbox.md.
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	rawPath, err := readPathFromMem(memFd, pathAddr)
	if err != nil {
		// Same fail-open path as above; memfd exists but read returned EIO
		// or similar (stale fd after execve).
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	resolved, err := resolveNotifPath(notif.PID, dirfd, rawPath)
	if err != nil {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	flags := classifyOpenFlags(notif.Data.Nr, notif.Data.Args, memFd)

	if entry, denied := matchDeniedPath(resolved, flags, phase.denyPaths); denied {
		if phase.auditWriter != nil {
			_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
				Type:     auditSeccompDeny,
				Syscall:  syscallName(notif.Data.Nr),
				Path:     resolved,
				Access:   denyAccessLabel(entry.Mode, flags),
				RulePath: entry.Path,
				Comm:     procComm(notif.PID),
				PID:      int(notif.PID),
				Ts:       time.Now().UnixNano(),
			})
		}
		_ = respondDeny(s.notifyFd, notif.ID)
		return
	}

	_ = respondContinue(s.notifyFd, notif.ID)
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
// Non-INET families (unix, netlink) are always allowed: they carry no
// egress. System resolvers reachable over unix sockets (systemd-resolved)
// therefore keep working even with allow_direct_dns=false — a documented
// gap in docs/sandbox-landlock.md.
func (n landlockNetworkPolicy) allowOutbound(family uint16, addr netip.Addr, port uint16) bool {
	if !n.Lockdown {
		return true
	}

	if family != unix.AF_INET && family != unix.AF_INET6 {
		return true
	}

	if addr.IsLoopback() {
		return port == n.ProxyPort || n.AllowBind || (n.AllowDirectDNS && port == dnsPort)
	}

	return n.AllowDirectDNS && port == dnsPort
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
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	addrPtr, addrLen, hasDest, ok := s.netSockaddrAddr(notif, phase)
	if !ok {
		s.denyNetworkConnect(notif, phase, "", "could not resolve destination address")
		return
	}
	if !hasDest {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	memFd := phase.memFdFor(notif.PID)
	if memFd == nil {
		s.denyNetworkConnect(notif, phase, "", "unreadable process memory")
		return
	}

	peer, err := readNetPeer(memFd, addrPtr, addrLen)
	if err != nil {
		s.denyNetworkConnect(notif, phase, "", err.Error())
		return
	}

	if phase.network.allowOutbound(peer.family, peer.addr, peer.port) {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	s.denyNetworkConnect(notif, phase, peer.String(), "network_via_proxy_only")
}

// netSockaddrAddr extracts the destination sockaddr pointer and length from
// the intercepted syscall's arguments. hasDest is false when the syscall
// carries no destination (sendto/sendmsg on a connected socket), in which
// case the caller continues without a policy decision.
func (s *seccompSupervisor) netSockaddrAddr(notif *seccompNotification, phase *seccompPhase) (addrPtr, addrLen uint64, hasDest, ok bool) {
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
		memFd := phase.memFdFor(notif.PID)
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
		_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
			Type:    auditNetworkDeny,
			Syscall: syscallName(notif.Data.Nr),
			Path:    target,
			Message: message,
			Comm:    procComm(notif.PID),
			PID:     int(notif.PID),
			Ts:      time.Now().UnixNano(),
		})
	}
	_ = respondDenyConnRefused(s.notifyFd, notif.ID)
}

// syscallName returns a human-readable name for known intercepted syscalls.
func syscallName(nr int32) string {
	switch nr {
	case int32(unix.SYS_OPENAT):
		return "openat"
	case int32(unix.SYS_OPENAT2):
		return "openat2"
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
