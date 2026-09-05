//go:build linux

package platform

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// pathOpKind groups the trapped path syscalls by the deny check they need.
type pathOpKind int

const (
	pathOpOpen     pathOpKind = iota // open, creat, openat, openat2
	pathOpRename                     // rename, renameat, renameat2
	pathOpLink                       // link, linkat
	pathOpRemove                     // unlink, unlinkat, rmdir
	pathOpCreate                     // mkdir, mkdirat, symlink, symlinkat
	pathOpTruncate                   // truncate
)

// pathOperand locates one path operand in the syscall arguments. A dirfd
// index of -1 means the syscall has none and resolves against the cwd.
type pathOperand struct {
	dirfd int
	path  int
}

// pathSyscall describes one trapped syscall that names a filesystem path.
// dst is set only for the two-path kinds (rename, link). flags is the index
// of the flags argument, or -1. openHow marks openat2, whose flags live in
// the struct open_how the argument points at. fixedFlags supplies the open
// flags a syscall implies when it has no flags argument (creat).
type pathSyscall struct {
	name       string
	kind       pathOpKind
	src        pathOperand
	dst        pathOperand
	flags      int
	openHow    bool
	fixedFlags int
}

func (p pathSyscall) hasDst() bool {
	return p.kind == pathOpRename || p.kind == pathOpLink
}

// seccompPathSyscalls is every syscall the supervisor traps for path denies:
// the *at forms every Linux architecture has, plus the forms of the running
// architecture (renameat is absent on riscv64, the legacy non-at forms on
// every arch but amd64). Landlock cannot subtract a protected subpath from a
// broad grant such as ${CWD}/**, so a process could rename, hard-link or
// remove a protected file if only openat were trapped.
var seccompPathSyscalls = buildPathSyscalls()

func buildPathSyscalls() map[uint32]pathSyscall {
	table := map[uint32]pathSyscall{
		unix.SYS_OPENAT:    {name: "openat", kind: pathOpOpen, src: pathOperand{dirfd: 0, path: 1}, flags: 2},
		unix.SYS_OPENAT2:   {name: "openat2", kind: pathOpOpen, src: pathOperand{dirfd: 0, path: 1}, flags: 2, openHow: true},
		unix.SYS_RENAMEAT2: {name: "renameat2", kind: pathOpRename, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: 4},
		unix.SYS_LINKAT:    {name: "linkat", kind: pathOpLink, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: 4},
		unix.SYS_UNLINKAT:  {name: "unlinkat", kind: pathOpRemove, src: pathOperand{dirfd: 0, path: 1}, flags: 2},
		unix.SYS_MKDIRAT:   {name: "mkdirat", kind: pathOpCreate, src: pathOperand{dirfd: 0, path: 1}, flags: -1},
		unix.SYS_SYMLINKAT: {name: "symlinkat", kind: pathOpCreate, src: pathOperand{dirfd: 1, path: 2}, flags: -1},
		unix.SYS_TRUNCATE:  {name: "truncate", kind: pathOpTruncate, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
	}
	for nr, op := range archPathSyscalls() {
		table[nr] = op
	}
	return table
}

// pathSyscallNumbers returns the trapped path syscall numbers in ascending
// order so the BPF program is deterministic.
func pathSyscallNumbers() []uint32 {
	nrs := make([]uint32, 0, len(seccompPathSyscalls))
	for nr := range seccompPathSyscalls {
		nrs = append(nrs, nr)
	}
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })
	return nrs
}

// pathOpKindForSyscall maps an audited syscall name back to its kind so the
// diagnostics layer classifies the violation. ok is false for syscalls that
// are not path operations (execve, connect).
func pathOpKindForSyscall(name string) (pathOpKind, bool) {
	for _, op := range seccompPathSyscalls {
		if op.name == name {
			return op.kind, true
		}
	}
	return 0, false
}

// canonicalPath resolves path the way the kernel resolves it during lookup:
// one component at a time, following each symlink before the components
// after it (so "link/.." lands in the link target's parent), and treating
// /proc/self as the notifying process rather than the supervisor. A
// component that does not exist ends resolution and the rest is appended
// lexically, so a path about to be created resolves to its real parent.
// followLeaf is false for the syscalls that act on a link itself (rename,
// link, unlink, mkdir, symlink) and for opens with O_NOFOLLOW.
//
// The supervisor reads the filesystem after the process issued the syscall
// and before the kernel resolves it. A process that swaps a symlink in that
// window defeats the check. This is the TOCTOU window every seccomp-notify
// path filter has (see docs/sandbox-landlock.md).
func canonicalPath(pid uint32, path string, followLeaf bool) string {
	const maxLinks = 40 // matches the kernel's ELOOP limit
	procSelf := "/proc/" + strconv.FormatUint(uint64(pid), 10)

	resolved := "/"
	rest := strings.Split(strings.TrimPrefix(path, "/"), "/")
	links := 0

	for len(rest) > 0 {
		component := rest[0]
		rest = rest[1:]

		switch component {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}

		next := filepath.Join(resolved, component)
		if next == "/proc/self" || next == "/proc/thread-self" {
			resolved = procSelf
			continue
		}

		info, err := os.Lstat(next)
		if err != nil {
			return filepath.Join(append([]string{next}, rest...)...)
		}

		if info.Mode()&os.ModeSymlink == 0 || (!followLeaf && len(rest) == 0) {
			resolved = next
			continue
		}

		links++
		target, err := os.Readlink(next)
		if links > maxLinks || err != nil {
			return filepath.Join(append([]string{next}, rest...)...)
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), rest...)
	}

	return resolved
}

// pathCoveredBy reports whether path is the deny entry or lies beneath it.
// An entry with a trailing slash prefix-matches; one without covers the
// path itself and anything beneath entry+"/".
func pathCoveredBy(path string, entry denyPathEntry) bool {
	if strings.HasSuffix(entry.Path, "/") {
		return strings.HasPrefix(path, entry.Path)
	}
	return path == entry.Path || strings.HasPrefix(path, entry.Path+"/")
}

// pathAboveDeny reports whether a deny entry lies strictly beneath path.
// Moving or replacing such a directory relocates the protected content.
func pathAboveDeny(path string, entry denyPathEntry) bool {
	return strings.HasPrefix(strings.TrimSuffix(entry.Path, "/"), path+"/")
}

// matchDeniedWriteTarget returns the deny entry that forbids creating,
// removing, truncating or writing path: a write or both-mode entry that
// covers it. With includeAncestors, any entry beneath path also matches,
// which is the rule for a rename or link destination: replacing ${CWD}/.git
// would replace .git/hooks with it.
func matchDeniedWriteTarget(path string, includeAncestors bool, denyPaths []denyPathEntry) (denyPathEntry, bool) {
	for _, entry := range denyPaths {
		if entry.Mode != denyRead && pathCoveredBy(path, entry) {
			return entry, true
		}
		if includeAncestors && pathAboveDeny(path, entry) {
			return entry, true
		}
	}
	return denyPathEntry{}, false
}

// matchDeniedMoveSource returns the deny entry that forbids moving or
// hard-linking path to a new name. Any entry counts, whatever its mode: a
// read-denied file under a new name is readable, and a moved ancestor
// directory carries the protected content with it.
func matchDeniedMoveSource(path string, denyPaths []denyPathEntry) (denyPathEntry, bool) {
	for _, entry := range denyPaths {
		if pathCoveredBy(path, entry) || pathAboveDeny(path, entry) {
			return entry, true
		}
	}
	return denyPathEntry{}, false
}

// matchDeniedMove checks a rename or link from src to dst. With exchange
// (RENAME_EXCHANGE) both paths move, so both take the source rule. The
// returned path is the operand that matched, for the audit event.
func matchDeniedMove(src, dst string, exchange bool, denyPaths []denyPathEntry) (denyPathEntry, string, bool) {
	if entry, denied := matchDeniedMoveSource(src, denyPaths); denied {
		return entry, src, true
	}
	if exchange {
		if entry, denied := matchDeniedMoveSource(dst, denyPaths); denied {
			return entry, dst, true
		}
	}
	if entry, denied := matchDeniedWriteTarget(dst, true, denyPaths); denied {
		return entry, dst, true
	}
	return denyPathEntry{}, "", false
}

// readSyscallFlags returns the flags argument of a path syscall, reading
// struct open_how from process memory for openat2. A failed read yields the
// syscall's implied flags, which for openat2 means read-only and follow.
func readSyscallFlags(op pathSyscall, args [6]uint64, memFd *os.File) int {
	if op.flags < 0 {
		return op.fixedFlags
	}
	if !op.openHow {
		return int(args[op.flags])
	}
	if memFd == nil {
		return op.fixedFlags
	}

	// struct open_how { u64 flags; u64 mode; u64 resolve; }
	buf := make([]byte, 8)
	if _, err := memFd.ReadAt(buf, int64(args[op.flags])); err != nil {
		return op.fixedFlags
	}
	return int(binary.LittleEndian.Uint64(buf))
}

// followsLeaf reports whether the kernel follows a symlink in the final
// component of the operand for this syscall and flags.
func followsLeaf(op pathSyscall, operand pathOperand, flags int) bool {
	switch op.kind {
	case pathOpOpen:
		return flags&unix.O_NOFOLLOW == 0
	case pathOpTruncate:
		return true
	case pathOpLink:
		return operand == op.src && flags&unix.AT_SYMLINK_FOLLOW != 0
	default:
		return false
	}
}

// resolveOperand reads one path operand from the notifying process and
// canonicalizes it.
func (s *seccompSupervisor) resolveOperand(notif *seccompNotification, memFd *os.File, operand pathOperand, followLeaf bool) (string, error) {
	rawPath, err := readPathFromMem(memFd, uintptr(notif.Data.Args[operand.path]))
	if err != nil {
		return "", err
	}

	dirfd := -100
	if operand.dirfd >= 0 {
		dirfd = dirfdFromArgs(notif.Data.Args[operand.dirfd])
	}

	return resolveNotifPath(notif.PID, dirfd, rawPath, followLeaf)
}

// handlePathOp enforces the deny list for one trapped path syscall. Every
// failure to read the process state fails open, as handleOpen always did:
// a denial would break the process on a supervisor fault rather than on
// policy.
func (s *seccompSupervisor) handlePathOp(notif *seccompNotification, phase *seccompPhase, op pathSyscall) {
	memFd := phase.memFdFor(notif.PID)
	if memFd == nil {
		// /proc/<pid>/mem is unreadable, typically after an execve that
		// cleared dumpable. See docs/sandbox.md for the enforcement gap.
		s.continueSyscall(notif.ID)
		return
	}
	defer closeMemFd(memFd)

	flags := readSyscallFlags(op, notif.Data.Args, memFd)

	src, err := s.resolveOperand(notif, memFd, op.src, followsLeaf(op, op.src, flags))
	if err != nil {
		s.continueSyscall(notif.ID)
		return
	}

	var (
		entry  denyPathEntry
		target = src
		denied bool
	)
	switch op.kind {
	case pathOpOpen:
		entry, denied = matchDeniedPath(src, flags, phase.denyPaths)
	case pathOpTruncate:
		entry, denied = matchDeniedPath(src, unix.O_WRONLY, phase.denyPaths)
	case pathOpRemove, pathOpCreate:
		entry, denied = matchDeniedWriteTarget(src, false, phase.denyPaths)
	case pathOpRename, pathOpLink:
		dst, err := s.resolveOperand(notif, memFd, op.dst, followsLeaf(op, op.dst, flags))
		if err != nil {
			s.continueSyscall(notif.ID)
			return
		}
		exchange := op.kind == pathOpRename && flags&unix.RENAME_EXCHANGE != 0
		entry, target, denied = matchDeniedMove(src, dst, exchange, phase.denyPaths)
	}

	if !denied {
		traceSeccompDecision("allow %s pid=%d path=%s", op.name, notif.PID, src)
		s.continueSyscall(notif.ID)
		return
	}

	access := "write"
	if op.kind == pathOpOpen {
		access = denyAccessLabel(entry.Mode, flags)
	}
	if phase.auditWriter != nil {
		_ = landlockWriteAuditEvent(phase.auditWriter, auditEvent{
			Type:     auditSeccompDeny,
			Syscall:  op.name,
			Path:     target,
			Access:   access,
			RulePath: entry.Path,
			Comm:     procComm(notif.PID),
			PID:      int(notif.PID),
			Ts:       time.Now().UnixNano(),
		})
	}
	traceSeccompDecision("deny %s pid=%d path=%s access=%s rule=%s", op.name, notif.PID, target, access, entry.Path)
	s.deny(notif.ID)
}

// resolveNotifPath turns a syscall path operand into a canonical absolute
// path. A relative path is anchored at /proc/<pid>/cwd or the dirfd's
// /proc/<pid>/fd entry (readlinkat is not intercepted). An empty path with
// a dirfd names the dirfd itself (AT_EMPTY_PATH).
func resolveNotifPath(pid uint32, dirfd int, rawPath string, followLeaf bool) (string, error) {
	joined := rawPath
	if !filepath.IsAbs(rawPath) {
		var base string
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
		// Join without Clean: ".." must apply after the symlink before it
		// is followed, which canonicalPath does component by component.
		joined = base + "/" + rawPath
	}

	return canonicalPath(pid, joined, followLeaf), nil
}
