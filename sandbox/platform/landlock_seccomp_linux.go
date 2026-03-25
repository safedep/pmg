//go:build linux

package platform

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctl constants for seccomp-notify, from Linux kernel UAPI include/uapi/linux/seccomp.h.
// These are _IOWR('!', N, struct) values.
const (
	_SECCOMP_IOCTL_NOTIF_RECV     = 0xc0502100
	_SECCOMP_IOCTL_NOTIF_SEND     = 0xc0182101
	_SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102
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
	auditNamespaceUnavailable auditEventType = "namespace_isolation_unavailable"
	auditMemFdOpenFailed      auditEventType = "memfd_open_failed"
)

// auditEvent represents a single security audit log entry.
type auditEvent struct {
	Type    auditEventType `json:"type"`
	Syscall string         `json:"syscall,omitempty"`
	Path    string         `json:"path,omitempty"`
	PID     int            `json:"pid,omitempty"`
	Message string         `json:"message,omitempty"`
	Error   string         `json:"error,omitempty"`
	Ts      int64          `json:"ts"`
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

// buildSeccompBPFFilter builds a classic BPF program that intercepts openat, openat2,
// execve, and execveat syscalls, returning SECCOMP_RET_USER_NOTIF for these and
// SECCOMP_RET_ALLOW for everything else.
func landlockBuildBPFFilter() (*unix.SockFprog, error) {
	filter := []unix.SockFilter{
		// [0] Load syscall number: BPF_LD | BPF_W | BPF_ABS, offset 0 (nr field in seccomp_data)
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// [1] JEQ SYS_OPENAT -> notify (jump to instruction 5)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 4, Jf: 0, K: uint32(unix.SYS_OPENAT)},
		// [2] JEQ SYS_OPENAT2 -> notify (jump to instruction 5)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, Jf: 0, K: uint32(unix.SYS_OPENAT2)},
		// [3] JEQ SYS_EXECVE -> notify (jump to instruction 5)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: uint32(unix.SYS_EXECVE)},
		// [4] JEQ SYS_EXECVEAT -> notify (jump to instruction 5)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: uint32(unix.SYS_EXECVEAT)},
		// [5] RET SECCOMP_RET_ALLOW
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		// [6] notify: RET SECCOMP_RET_USER_NOTIF
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
	}

	return &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}, nil
}

// landlockProbeSeccompNotify verifies that seccomp user notification is available on the
// running kernel. It attempts to install a trivial seccomp filter with the
// NEW_LISTENER flag. Returns nil if available, an error if not (kernel < 5.0).

// isPathDenied checks if a path should be denied based on the deny list and open flags.
// flags uses O_ACCMODE constants (O_RDONLY, O_WRONLY, O_RDWR).
// Matching rules:
//   - Exact match: /home/user/.env matches deny /home/user/.env
//   - Directory prefix: /home/user/.ssh/id_rsa matches deny /home/user/.ssh/
//     (deny path ends with /)
//   - Must NOT match partial names: /home/.envrc does NOT match deny /home/.env
func isPathDenied(path string, flags int, denyPaths []denyPathEntry) bool {
	accessMode := flags & unix.O_ACCMODE

	for _, entry := range denyPaths {
		matched := false
		if strings.HasSuffix(entry.Path, "/") {
			// Directory prefix match: path must start with the deny prefix.
			matched = strings.HasPrefix(path, entry.Path)
		} else {
			// Exact match only.
			matched = path == entry.Path
		}

		if !matched {
			continue
		}

		switch entry.Mode {
		case denyRead:
			if accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR {
				return true
			}
		case denyWrite:
			if accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR {
				return true
			}
		case denyBoth:
			return true
		}
	}

	return false
}

// isExecDenied checks if a path matches the deny exec list.
// Same matching rules as isPathDenied but no flag check.
func isExecDenied(path string, denyExec []string) bool {
	for _, entry := range denyExec {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(path, entry) {
				return true
			}
		} else {
			if path == entry {
				return true
			}
		}
	}

	return false
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
	memFd     *os.File
	denyPaths []denyPathEntry
	denyExec  []string
	auditWriter io.Writer
}

// seccompSupervisor manages the seccomp notification loop.
type seccompSupervisor struct {
	notifyFd int
	phase    atomic.Pointer[seccompPhase]
	loopDone chan struct{}
}

// newLandlockSupervisor installs a seccomp-notify BPF filter and starts the
// notification loop goroutine. In phase 1 (before Enforce is called), all
// notifications are auto-continued.
func newLandlockSupervisor() (*seccompSupervisor, error) {
	// Build the BPF filter inline so the filter slice stays alive on the stack
	// during the seccomp syscall. If we return the slice from a function,
	// the GC may collect it before the syscall reads the pointer.
	filter := []unix.SockFilter{
		// [0] Load syscall number
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// [1-4] Check against intercepted syscalls
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 4, Jf: 0, K: uint32(unix.SYS_OPENAT)},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, Jf: 0, K: uint32(unix.SYS_OPENAT2)},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: uint32(unix.SYS_EXECVE)},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: uint32(unix.SYS_EXECVEAT)},
		// [5] Allow all other syscalls
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		// [6] Notify supervisor for intercepted syscalls
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// TSYNC atomically applies the filter to ALL threads in the process.
	// This is critical for Go's multi-threaded runtime: the child process
	// (spawned via exec.Cmd.Start) may be forked from any runtime thread.
	// Without TSYNC, only the current thread gets the filter.
	flags := uintptr(
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER |
			unix.SECCOMP_FILTER_FLAG_TSYNC |
			unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
	)

	fd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		2, // SECCOMP_SET_MODE_FILTER
		flags,
		uintptr(unsafe.Pointer(&prog)),
	)
	runtime.KeepAlive(&filter)
	runtime.KeepAlive(&prog)

	if errno == unix.EINVAL {
		// Retry without WAIT_KILLABLE_RECV (kernel < 5.19).
		flags = uintptr(
			unix.SECCOMP_FILTER_FLAG_NEW_LISTENER |
				unix.SECCOMP_FILTER_FLAG_TSYNC,
		)
		fd, _, errno = unix.Syscall(
			unix.SYS_SECCOMP,
			2,
			flags,
			uintptr(unsafe.Pointer(&prog)),
		)
		runtime.KeepAlive(&filter)
		runtime.KeepAlive(&prog)
	}

	if errno != 0 {
		return nil, fmt.Errorf("seccomp SET_MODE_FILTER: %w", errno)
	}

	s := &seccompSupervisor{
		notifyFd: int(fd),
		loopDone: make(chan struct{}),
	}

	go s.loop()

	return s, nil
}

// Enforce transitions the supervisor to enforcement mode. From this point on,
// syscalls from childPID are checked against the deny lists.
func (s *seccompSupervisor) Enforce(childPID int, memFd *os.File, denyPaths []denyPathEntry, denyExec []string, auditWriter io.Writer) error {
	p := &seccompPhase{
		enforcing:   true,
		childPID:    uint32(childPID),
		memFd:       memFd,
		denyPaths:   denyPaths,
		denyExec:    denyExec,
		auditWriter: auditWriter,
	}
	s.phase.Store(p)
	return nil
}

// Stop closes the notification fd and waits for the loop goroutine to exit.
func (s *seccompSupervisor) Stop() error {
	unix.Close(s.notifyFd)
	<-s.loopDone
	return nil
}

// loop is the main notification processing goroutine.
func (s *seccompSupervisor) loop() {
	defer close(s.loopDone)

	for {
		notif, err := recvNotification(s.notifyFd)
		if err != nil {
			// fd closed or unrecoverable error — exit loop.
			return
		}

		phase := s.phase.Load()
		if phase == nil || !phase.enforcing {
			_ = respondContinue(s.notifyFd, notif.ID)
			continue
		}

		// Only enforce for the expected child PID.
		if notif.PID != phase.childPID {
			_ = respondContinue(s.notifyFd, notif.ID)
			continue
		}

		switch notif.Data.Nr {
		case int32(unix.SYS_EXECVE), int32(unix.SYS_EXECVEAT):
			s.handleExec(notif, phase)
		case int32(unix.SYS_OPENAT), int32(unix.SYS_OPENAT2):
			s.handleOpen(notif, phase)
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

	rawPath, err := readPathFromMem(phase.memFd, pathAddr)
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

	if isExecDenied(resolved, phase.denyExec) {
		if phase.auditWriter != nil {
			_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
				Type:    auditSeccompDeny,
				Syscall: syscallName(notif.Data.Nr),
				Path:    resolved,
				PID:     int(notif.PID),
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

	rawPath, err := readPathFromMem(phase.memFd, pathAddr)
	if err != nil {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	resolved, err := resolveNotifPath(notif.PID, dirfd, rawPath)
	if err != nil {
		_ = respondContinue(s.notifyFd, notif.ID)
		return
	}

	flags := classifyOpenFlags(notif.Data.Nr, notif.Data.Args, phase.memFd)

	if isPathDenied(resolved, flags, phase.denyPaths) {
		if phase.auditWriter != nil {
			_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
				Type:    auditSeccompDeny,
				Syscall: syscallName(notif.Data.Nr),
				Path:    resolved,
				PID:     int(notif.PID),
			})
		}
		_ = respondDeny(s.notifyFd, notif.ID)
		return
	}

	_ = respondContinue(s.notifyFd, notif.ID)
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
	default:
		return fmt.Sprintf("syscall_%d", nr)
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
	resp := seccompNotifResp{
		ID:    id,
		Error: -int32(unix.EACCES),
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
		return fmt.Errorf("ioctl SECCOMP_IOCTL_NOTIF_SEND (deny): %w", errno)
	}
}
