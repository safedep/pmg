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
//  2. Installs the seccomp-notify filter WITHOUT PR_SET_NO_NEW_PRIVS. This is
//     the whole point of the user-ns indirection: without NNP, subsequent
//     execve(2)s in the target tree do NOT reset the dumpable flag to 0, so
//     the helper can keep opening /proc/<pid>/mem for descendants and resolve
//     openat(2) path arguments.
//  3. Sends the notify fd back to the helper over a socketpair on
//     notifySocketFd (fd number preserved via cmd.ExtraFiles).
//  4. Applies Landlock restrictions.
//  5. execve(2)s the target binary. The seccomp filter survives execve
//     (filters are inherited) and applies to the target and all descendants.
//
// Returns an error only if the shim fails before execve. On success the
// shim process is replaced by the target and this function does not return.
func RunLandlockShim(policyFile string, notifySocketFd int, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("shim: no target command")
	}

	// Pin to the OS thread. Without TSYNC the filter applies only to the
	// current thread; we must also execve from this thread so the target
	// inherits the filter.
	runtime.LockOSThread()

	// 1. Load policy (the file is owned by the helper; shim doesn't delete it).
	policy, err := readLandlockPolicyFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("shim: read policy: %w", err)
	}

	// 2. Install seccomp filter. Whether we intercept openat/openat2 depends
	// on whether the policy has any deny rules — matches helper logic.
	interceptOpen := len(policy.DenyPaths) > 0
	notifyFd, err := shimInstallSeccomp(interceptOpen)
	if err != nil {
		return fmt.Errorf("shim: install seccomp: %w", err)
	}

	// 3. Hand the notify fd to the helper via SCM_RIGHTS.
	if err := sendFdToSocket(notifySocketFd, notifyFd); err != nil {
		return fmt.Errorf("shim: send notify fd: %w", err)
	}
	// Close the notify fd in our process — the helper owns it now and the
	// kernel routes notifications via the shared file description.
	_ = unix.Close(notifyFd)
	_ = unix.Close(notifySocketFd)

	// 4. Apply Landlock.
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

	// 5. execve target. Args[0] is the program path.
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
func shimInstallSeccomp(interceptOpen bool) (int, error) {
	var filter []unix.SockFilter
	if interceptOpen {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 4, Jf: 0, K: uint32(unix.SYS_OPENAT)},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, Jf: 0, K: uint32(unix.SYS_OPENAT2)},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: uint32(unix.SYS_EXECVE)},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: uint32(unix.SYS_EXECVEAT)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		}
	} else {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: uint32(unix.SYS_EXECVE)},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: uint32(unix.SYS_EXECVEAT)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}

	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	fd, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flags,
		uintptr(unsafe.Pointer(&prog)),
	)
	runtime.KeepAlive(&filter)
	runtime.KeepAlive(&prog)
	if errno != 0 {
		return -1, fmt.Errorf("SECCOMP_SET_MODE_FILTER without NNP (user-ns CAP_SYS_ADMIN required): %w", errno)
	}
	return int(fd), nil
}

// sendFdToSocket sends `fd` over a connected unix-domain socket using
// SCM_RIGHTS. This transfers the fd to the peer process atomically.
func sendFdToSocket(sockFd, fd int) error {
	rights := unix.UnixRights(fd)
	buf := []byte{0}
	iov := unix.Iovec{Base: &buf[0], Len: 1}
	msg := unix.Msghdr{Iov: &iov, Iovlen: 1, Control: &rights[0]}
	msg.SetControllen(len(rights))
	_, _, errno := unix.Syscall(
		unix.SYS_SENDMSG,
		uintptr(sockFd),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)
	runtime.KeepAlive(&buf)
	runtime.KeepAlive(&iov)
	runtime.KeepAlive(&rights)
	runtime.KeepAlive(&msg)
	if errno != 0 {
		return fmt.Errorf("sendmsg: %w", errno)
	}
	return nil
}
