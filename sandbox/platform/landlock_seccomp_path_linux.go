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

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox/util"
	"golang.org/x/sys/unix"
)

// pathOpKind groups the trapped path syscalls by the deny check they need.
type pathOpKind int

const (
	pathOpOpen     pathOpKind = iota // open, creat, openat, openat2
	pathOpRename                     // rename, renameat, renameat2
	pathOpLink                       // link, linkat
	pathOpRemove                     // unlink, unlinkat, rmdir
	pathOpCreate                     // mkdir, mkdirat, mknod, mknodat
	pathOpSymlink                    // symlink, symlinkat
	pathOpTruncate                   // truncate
	pathOpChroot                     // chroot, always denied
)

// pathOperand locates one path operand in the syscall arguments. A dirfd
// index of -1 means AT_FDCWD.
type pathOperand struct {
	dirfd int
	path  int
}

// pathSyscall describes one trapped syscall. flags is the index of the
// flags argument, or -1. openHow marks openat2. fixedFlags are the open
// flags creat implies.
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

// seccompPathSyscalls is every syscall the supervisor traps for path denies.
// Landlock cannot take a subpath out of a broad grant, so rename, link and
// unlink must be trapped as well as open.
var seccompPathSyscalls = buildPathSyscalls()

func buildPathSyscalls() map[uint32]pathSyscall {
	table := map[uint32]pathSyscall{
		unix.SYS_OPENAT:    {name: "openat", kind: pathOpOpen, src: pathOperand{dirfd: 0, path: 1}, flags: 2},
		unix.SYS_OPENAT2:   {name: "openat2", kind: pathOpOpen, src: pathOperand{dirfd: 0, path: 1}, flags: 2, openHow: true},
		unix.SYS_RENAMEAT2: {name: "renameat2", kind: pathOpRename, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: 4},
		unix.SYS_LINKAT:    {name: "linkat", kind: pathOpLink, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: 4},
		unix.SYS_UNLINKAT:  {name: "unlinkat", kind: pathOpRemove, src: pathOperand{dirfd: 0, path: 1}, flags: 2},
		unix.SYS_MKDIRAT:   {name: "mkdirat", kind: pathOpCreate, src: pathOperand{dirfd: 0, path: 1}, flags: -1},
		unix.SYS_MKNODAT:   {name: "mknodat", kind: pathOpCreate, src: pathOperand{dirfd: 0, path: 1}, flags: -1},
		unix.SYS_SYMLINKAT: {name: "symlinkat", kind: pathOpSymlink, src: pathOperand{dirfd: 1, path: 2}, flags: -1},
		unix.SYS_TRUNCATE:  {name: "truncate", kind: pathOpTruncate, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
		unix.SYS_CHROOT:    {name: "chroot", kind: pathOpChroot, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
	}
	for nr, op := range archPathSyscalls() {
		table[nr] = op
	}
	return table
}

// pathSyscallNumbers returns the trapped syscall numbers in ascending order,
// so the BPF program is deterministic.
func pathSyscallNumbers() []uint32 {
	nrs := make([]uint32, 0, len(seccompPathSyscalls))
	for nr := range seccompPathSyscalls {
		nrs = append(nrs, nr)
	}
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })
	return nrs
}

// pathOpKindForSyscall maps an audited syscall name to its kind. ok is false
// for a syscall that is not a path operation.
func pathOpKindForSyscall(name string) (pathOpKind, bool) {
	for _, op := range seccompPathSyscalls {
		if op.name == name {
			return op.kind, true
		}
	}
	return 0, false
}

// canonicalPath resolves path as the kernel does: one component at a time,
// each symlink before the components after it, /proc/self as the notifying
// process. A missing component ends the walk and the rest is appended
// lexically. root is the floor: ".." stops there and an absolute symlink
// target restarts there, as under chroot(2) and RESOLVE_IN_ROOT. Under a
// root other than "/" /proc/self is left alone. followLeaf is false for the
// syscalls that act on a link itself and for O_NOFOLLOW.
func canonicalPath(pid uint32, root, path string, followLeaf bool) string {
	const maxLinks = 40 // matches the kernel's ELOOP limit
	procSelf := "/proc/" + strconv.FormatUint(uint64(pid), 10)

	root = filepath.Clean(root)
	resolved := root
	rest := strings.Split(pathBelowRoot(root, path), "/")
	links := 0

	for len(rest) > 0 {
		component := rest[0]
		rest = rest[1:]

		switch component {
		case "", ".":
			continue
		case "..":
			if resolved != root {
				resolved = filepath.Dir(resolved)
			}
			continue
		}

		next := filepath.Join(resolved, component)
		if root == "/" && (next == "/proc/self" || next == "/proc/thread-self") {
			resolved = procSelf
			continue
		}

		info, err := os.Lstat(next)
		if err != nil {
			return clampToRoot(root, filepath.Join(append([]string{next}, rest...)...))
		}

		if info.Mode()&os.ModeSymlink == 0 || (!followLeaf && len(rest) == 0) {
			resolved = next
			continue
		}

		links++
		target, err := os.Readlink(next)
		if links > maxLinks || err != nil {
			return clampToRoot(root, filepath.Join(append([]string{next}, rest...)...))
		}
		if filepath.IsAbs(target) {
			resolved = root
		}
		rest = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), rest...)
	}

	return resolved
}

// pathBelowRoot returns path relative to root, or path itself when it does
// not lie below root.
func pathBelowRoot(root, path string) string {
	if root == "/" {
		return strings.TrimPrefix(path, "/")
	}
	if path == root {
		return ""
	}
	if strings.HasPrefix(path, root+"/") {
		return path[len(root)+1:]
	}
	return strings.TrimPrefix(path, "/")
}

// clampToRoot keeps a lexical tail from escaping the floor through "..". The
// kernel fails such a lookup, so only the floor matters.
func clampToRoot(root, path string) string {
	if root == "/" || path == root || strings.HasPrefix(path, root+"/") {
		return path
	}
	return root
}

// pathCoveredBy reports whether path is the deny entry or lies beneath it.
// A trailing slash prefix-matches. A glob entry covers a path whose name or
// ancestor name matches, so a file created after setup is covered.
func pathCoveredBy(path string, entry denyPathEntry) bool {
	if strings.HasPrefix(entry.Path, "**/") {
		return anywhereCoversPath(strings.TrimPrefix(entry.Path, "**/"), path)
	}
	if util.ContainsGlob(entry.Path) {
		return globCoversPath(entry.Path, path)
	}
	if strings.HasSuffix(entry.Path, "/") {
		return strings.HasPrefix(path, entry.Path)
	}
	return path == entry.Path || strings.HasPrefix(path, entry.Path+"/")
}

// globCoversPath matches pattern against path and each ancestor. A
// malformed pattern matches nothing.
func globCoversPath(pattern, path string) bool {
	for p := path; ; p = filepath.Dir(p) {
		if ok, err := filepath.Match(pattern, p); err != nil {
			return false
		} else if ok {
			return true
		}
		if p == "/" || p == "." {
			return false
		}
	}
}

// resolveDenyEntries adds the canonical form of each entry next to the
// lexical one. Syscall paths are canonical, so an entry under a symlinked
// directory (~/.ssh -> ~/dotfiles/ssh) would not match by its lexical path.
func resolveDenyEntries(pid uint32, entries []denyPathEntry) []denyPathEntry {
	out := make([]denyPathEntry, 0, 2*len(entries))
	for _, entry := range entries {
		out = append(out, entry)
		if resolved := canonicalDenyPath(pid, entry.Path); resolved != entry.Path {
			out = append(out, denyPathEntry{Path: resolved, Mode: entry.Mode})
		}
	}
	return out
}

// resolveDenyExec is resolveDenyEntries for the deny_exec list.
func resolveDenyExec(pid uint32, entries []string) []string {
	out := make([]string, 0, 2*len(entries))
	for _, entry := range entries {
		out = append(out, entry)
		if resolved := canonicalDenyPath(pid, entry); resolved != entry {
			out = append(out, resolved)
		}
	}
	return out
}

// canonicalDenyPath resolves the symlinks in a deny path. For a glob only
// the directory before the first glob component is resolved.
func canonicalDenyPath(pid uint32, path string) string {
	if !util.ContainsGlob(path) {
		return canonicalPath(pid, "/", path, true)
	}

	components := strings.Split(path, "/")
	for i, component := range components {
		if util.ContainsGlob(component) {
			base := strings.Join(components[:i], "/")
			if base == "" {
				return path
			}
			return filepath.Join(canonicalPath(pid, "/", base, true), strings.Join(components[i:], "/"))
		}
	}
	return path
}

// anywhereCoversPath matches a "**/<name>" deny against every run of
// components in path: "**/.ssh" covers /home/u/.ssh/id_rsa.
func anywhereCoversPath(name, path string) bool {
	want := strings.Split(name, "/")
	have := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for start := 0; start+len(want) <= len(have); start++ {
		matched := true
		for i, w := range want {
			if ok, err := filepath.Match(w, have[start+i]); err != nil || !ok {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// pathAboveDeny reports whether a deny entry lies strictly beneath path. A
// "**/" entry can lie beneath any directory, so it never counts.
func pathAboveDeny(path string, entry denyPathEntry) bool {
	if strings.HasPrefix(entry.Path, "**/") {
		return false
	}
	return strings.HasPrefix(strings.TrimSuffix(entry.Path, "/"), path+"/")
}

// matchDeniedWriteTarget returns the write or both-mode entry that covers
// path. With includeAncestors an entry beneath path matches too: a tree
// renamed onto ${CWD}/.git replaces .git/hooks.
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

// matchDeniedMoveSource returns the entry that forbids moving or linking
// path away. Any mode counts: a read-denied file under a new name is
// readable, and a moved ancestor carries the protected content.
func matchDeniedMoveSource(path string, denyPaths []denyPathEntry) (denyPathEntry, bool) {
	for _, entry := range denyPaths {
		if pathCoveredBy(path, entry) || pathAboveDeny(path, entry) {
			return entry, true
		}
	}
	return denyPathEntry{}, false
}

// matchDeniedMove checks a rename or link from src to dst. RENAME_EXCHANGE
// moves both paths, so both take the source rule.
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

// openat2Args are the fields of struct open_how the supervisor acts on.
type openat2Args struct {
	flags   int
	resolve uint64
}

// readSyscallFlags returns the flags of a path syscall, reading struct
// open_how for openat2. An unreadable open_how fails open as a read-only
// open in the caller's root.
func readSyscallFlags(op pathSyscall, args [6]uint64, memFd *os.File) openat2Args {
	if op.flags < 0 {
		return openat2Args{flags: op.fixedFlags}
	}
	if !op.openHow {
		return openat2Args{flags: int(args[op.flags])}
	}
	if memFd == nil {
		return openat2Args{flags: op.fixedFlags}
	}

	// struct open_how { u64 flags; u64 mode; u64 resolve; }
	buf := make([]byte, unix.SizeofOpenHow)
	if _, err := memFd.ReadAt(buf, int64(args[op.flags])); err != nil {
		return openat2Args{flags: op.fixedFlags}
	}
	return openat2Args{
		flags:   int(binary.LittleEndian.Uint64(buf[0:8])),
		resolve: binary.LittleEndian.Uint64(buf[16:24]),
	}
}

// openAccessFlags raises O_RDONLY to O_RDWR when O_CREAT or O_TRUNC is set.
// Both write to the path, and Linux truncates on O_RDONLY|O_TRUNC.
func openAccessFlags(flags int) int {
	if flags&(unix.O_CREAT|unix.O_TRUNC) != 0 && flags&unix.O_ACCMODE == unix.O_RDONLY {
		return flags&^unix.O_ACCMODE | unix.O_RDWR
	}
	return flags
}

// followsLeaf reports whether the kernel follows a symlink in the final
// component of the operand.
func followsLeaf(op pathSyscall, operand pathOperand, flags int) bool {
	switch op.kind {
	case pathOpOpen:
		return flags&unix.O_NOFOLLOW == 0
	case pathOpTruncate, pathOpChroot:
		return true
	case pathOpLink:
		return operand == op.src && flags&unix.AT_SYMLINK_FOLLOW != 0
	default:
		return false
	}
}

// resolveOperand reads one path operand from the notifying process.
func (s *seccompSupervisor) resolveOperand(notif *seccompNotification, memFd *os.File, operand pathOperand, followLeaf bool, resolve uint64) (string, error) {
	rawPath, err := readPathFromMem(memFd, uintptr(notif.Data.Args[operand.path]))
	if err != nil {
		return "", err
	}

	dirfd := -100
	if operand.dirfd >= 0 {
		dirfd = dirfdFromArgs(notif.Data.Args[operand.dirfd])
	}

	return resolveSyscallPath(notif.PID, dirfd, rawPath, followLeaf, resolve)
}

// handlePathOp enforces the deny list for one trapped path syscall.
// Unreadable process state fails open, as the open handler always did.
func (s *seccompSupervisor) handlePathOp(notif *seccompNotification, phase *seccompPhase, op pathSyscall) {
	memFd := phase.memFdFor(notif.PID)
	if memFd == nil {
		// Unreadable after an execve that cleared dumpable. See docs/sandbox.md.
		s.continueSyscall(notif.ID)
		return
	}
	defer closeMemFd(memFd)

	args := readSyscallFlags(op, notif.Data.Args, memFd)
	flags := args.flags
	if op.kind == pathOpOpen {
		flags = openAccessFlags(flags)
	}

	src, err := s.resolveOperand(notif, memFd, op.src, followsLeaf(op, op.src, flags), args.resolve)
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
	case pathOpSymlink:
		// A symlink at an ancestor of a protected path redirects the subtree.
		entry, denied = matchDeniedWriteTarget(src, true, phase.denyPaths)
	case pathOpRename, pathOpLink:
		dst, err := s.resolveOperand(notif, memFd, op.dst, followsLeaf(op, op.dst, flags), args.resolve)
		if err != nil {
			s.continueSyscall(notif.ID)
			return
		}
		exchange := op.kind == pathOpRename && flags&unix.RENAME_EXCHANGE != 0
		entry, target, denied = matchDeniedMove(src, dst, exchange, phase.denyPaths)
	case pathOpChroot:
		// Landlock does not hook chroot and root in the user namespace keeps
		// CAP_SYS_CHROOT. A new root changes what every absolute path means.
		entry, denied = denyPathEntry{Path: src, Mode: denyWrite}, true
	}

	// A recycled pid must not be judged on another process's /proc state.
	if !s.notifValid(notif.ID) {
		s.deny(notif.ID)
		return
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
		err := landlockWriteAuditEvent(phase.auditWriter, auditEvent{
			Type:     auditSeccompDeny,
			Syscall:  op.name,
			Path:     target,
			Access:   access,
			RulePath: entry.Path,
			Comm:     procComm(notif.PID),
			PID:      int(notif.PID),
			Ts:       time.Now().UnixNano(),
		})
		if err != nil {
			log.Warnf("sandbox: failed to record the %s denial of %s: %v", op.name, target, err)
		}
	}
	traceSeccompDecision("deny %s pid=%d path=%s access=%s rule=%s", op.name, notif.PID, target, access, entry.Path)
	s.deny(notif.ID)
}

// resolveSyscallPath turns a path operand into the canonical absolute path
// the kernel will act on. A relative path is anchored at /proc/<pid>/cwd or
// the dirfd, an absolute one at /proc/<pid>/root. Under RESOLVE_IN_ROOT the
// dirfd is the floor and a leading slash means the dirfd. An empty path
// names the dirfd. The supervisor refuses chroot, so the root is read only
// for an absolute path, where it is the anchor, and "/" is the floor
// elsewhere.
func resolveSyscallPath(pid uint32, dirfd int, rawPath string, followLeaf bool, resolve uint64) (string, error) {
	dirPath := func() (string, error) {
		if dirfd == -100 {
			return procLink(pid, "cwd")
		}
		return procLink(pid, "fd/"+strconv.Itoa(dirfd))
	}

	floor := "/"
	var joined string
	switch {
	case resolve&unix.RESOLVE_IN_ROOT != 0:
		base, err := dirPath()
		if err != nil {
			return "", err
		}
		floor = base
		joined = base + "/" + strings.TrimLeft(rawPath, "/")
	case filepath.IsAbs(rawPath):
		root, err := procLink(pid, "root")
		if err != nil {
			return "", err
		}
		floor = root
		joined = strings.TrimSuffix(root, "/") + rawPath
	default:
		base, err := dirPath()
		if err != nil {
			return "", err
		}
		// No Clean: ".." must apply after the symlink before it.
		joined = base + "/" + rawPath
	}

	return canonicalPath(pid, floor, joined, followLeaf), nil
}

// resolveNotifPath is resolveSyscallPath for syscalls without resolve flags.
func resolveNotifPath(pid uint32, dirfd int, rawPath string, followLeaf bool) (string, error) {
	return resolveSyscallPath(pid, dirfd, rawPath, followLeaf, 0)
}

func procLink(pid uint32, name string) (string, error) {
	link := fmt.Sprintf("/proc/%d/%s", pid, name)
	target, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", link, err)
	}
	return target, nil
}
