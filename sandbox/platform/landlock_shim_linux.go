//go:build linux

package platform

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

// RunLandlockShim is the inside-user-namespace entry point. It is invoked by
// the helper as a direct child forked with CLONE_NEWUSER + uid map 0->host.
// As uid-0-in-ns with CAP_SYS_ADMIN, it:
//
//  1. Loads the serialised landlockExecPolicy from policyFile.
//  2. Applies Landlock restrictions. This runs BEFORE the seccomp filter is
//     installed: populating the ruleset opens every rule path, and the
//     supervisor would enforce the policy's deny list against the shim
//     itself, aborting it with EACCES before exec.
//  3. Installs the seccomp-notify filter WITHOUT PR_SET_NO_NEW_PRIVS. This is
//     the whole point of the user-ns indirection: without NNP, subsequent
//     execve(2)s in the target tree do NOT reset the dumpable flag to 0, so
//     the helper can keep opening /proc/<pid>/mem for descendants and resolve
//     openat(2) path arguments.
//  4. Sends the notify fd back to the helper over a socketpair on
//     notifySocketFd (fd number preserved via cmd.ExtraFiles).
//  5. execve(2)s the target binary. The seccomp filter survives execve
//     (filters are inherited) and applies to the target and all descendants.
//
// Returns an error only if the shim fails before execve. On success the
// shim process is replaced by the target and this function does not return.
func RunLandlockShim(policyFile string, notifySocketFd int, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("shim: no target command")
	}

	// Without TSYNC the filter applies only to this thread; we must also
	// execve from this same thread so the target inherits it.
	runtime.LockOSThread()

	// The policy file is owned by the helper; shim doesn't delete it.
	policy, err := readLandlockPolicyFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("shim: read policy: %w", err)
	}

	var rules []landlock.Rule
	for _, r := range policy.FilesystemRules {
		access := landlockAdjustAccessForPath(r.Path, r.Access)
		rules = append(rules, landlock.PathAccess(
			landlock.AccessFSSet(access), r.Path,
		).IgnoreIfMissing())
	}
	cfg := landlockSelectConfig(policy)
	if err := cfg.BestEffort().RestrictPaths(rules...); err != nil {
		return fmt.Errorf("shim: landlock restrict: %w", err)
	}

	syscalls := landlockNotifySyscalls(policy.Network, len(policy.DenyPaths) > 0)
	notifyFd, err := shimInstallSeccomp(syscalls)
	if err != nil {
		return fmt.Errorf("shim: install seccomp: %w", err)
	}

	if err := sendFdToSocket(notifySocketFd, notifyFd); err != nil {
		return fmt.Errorf("shim: send notify fd: %w", err)
	}
	// Helper owns the notify fd now; kernel routes notifications via the
	// shared file description.
	_ = unix.Close(notifyFd)
	_ = unix.Close(notifySocketFd)

	target := args[0]
	env := os.Environ()
	if len(policy.Env) > 0 {
		env = policy.Env
	}
	if err := unix.Exec(target, args, env); err != nil {
		return fmt.Errorf("shim: exec %s: %w", target, err)
	}
	return nil // unreachable
}

// shimInstallSeccomp installs the seccomp-notify filter WITHOUT
// PR_SET_NO_NEW_PRIVS. The kernel accepts this only when the caller has
// CAP_SYS_ADMIN in its user namespace; the helper arranges that by cloning
// us with CLONE_NEWUSER + uid/gid mapping that makes us uid 0 in the new ns.
func shimInstallSeccomp(syscalls []uint32) (int, error) {
	prog := landlockBuildNotifyFilter(syscalls...)

	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	fd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flags,
		uintptr(unsafe.Pointer(prog)),
	)
	runtime.KeepAlive(prog)
	if errno != 0 {
		return -1, fmt.Errorf("SECCOMP_SET_MODE_FILTER without NNP (user-ns CAP_SYS_ADMIN required): %w", errno)
	}
	return int(fd), nil
}

// shimMmsghdr matches the kernel's `struct mmsghdr` (x/sys/unix does not
// export one): the msg_hdr followed by the returned message length.
type shimMmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

// sendFdToSocket sends `fd` over a connected unix-domain socket using
// SCM_RIGHTS. This transfers the fd to the peer process atomically.
//
// The send uses sendmmsg, not sendmsg: under network lockdown the seccomp
// filter traps sendmsg(2) and is installed BEFORE this handoff, so a sendmsg
// here would trap the shim's own fd pass. The shim would block waiting for a
// notification response that only the (not yet received) listener could
// produce — a self-deadlock. sendmmsg is not in the trap set.
func sendFdToSocket(sockFd, fd int) error {
	rights := unix.UnixRights(fd)
	buf := []byte{0}
	iov := unix.Iovec{Base: &buf[0], Len: 1}
	msg := unix.Msghdr{Iov: &iov, Iovlen: 1, Control: &rights[0]}
	msg.SetControllen(len(rights))
	mmsg := shimMmsghdr{Hdr: msg}

	_, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(sockFd),
		uintptr(unsafe.Pointer(&mmsg)),
		1, // vlen
		0, // flags
		0, 0,
	)
	runtime.KeepAlive(&buf)
	runtime.KeepAlive(&iov)
	runtime.KeepAlive(&rights)
	runtime.KeepAlive(&mmsg)
	if errno != 0 {
		return fmt.Errorf("sendmmsg: %w", errno)
	}
	if mmsg.Len != uint32(len(buf)) {
		return fmt.Errorf("sendmmsg: short write (%d of %d bytes)", mmsg.Len, len(buf))
	}
	return nil
}
