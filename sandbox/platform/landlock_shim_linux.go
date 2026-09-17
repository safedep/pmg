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

// RunLandlockShim runs inside the user namespace that the helper created.
// It applies Landlock, installs the seccomp filter, sends the notify fd to
// the helper and calls execve. It returns only on a failure before execve.
func RunLandlockShim(policyFile string, notifySocketFd int, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("shim: no target command")
	}

	// Without TSYNC the filter applies to this thread only. The execve must
	// run on the same thread so the target inherits the filter.
	runtime.LockOSThread()

	policy, err := readLandlockPolicyFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("shim: read policy: %w", err)
	}

	// Landlock runs before seccomp. It opens each rule path, and the
	// supervisor would deny those opens against the deny list.
	rules := shimFilesystemRules(policy.FilesystemRules)
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

// shimInstallSeccomp does not set PR_SET_NO_NEW_PRIVS. Landlock has set it
// already. On a kernel without Landlock the install needs CAP_SYS_ADMIN in
// the user namespace, which the shim holds until execve.
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

// sendFdToSocket uses sendmmsg, not sendmsg. Under network lockdown the
// filter traps sendmsg, and the filter is already installed. A trapped send
// would wait for a reply from the listener that this send carries.
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

// shimFilesystemRules builds the Landlock rules. A rule binds to the inode
// at restrict time, so a path that cannot be opened grants nothing.
// IgnoreIfMissing covers a missing path, but a path through a file, such as
// .git/config in a linked worktree where .git is a file, fails with ENOTDIR
// and would abort the sandbox. Skip every path that does not stat.
func shimFilesystemRules(fsRules []landlockPathRule) []landlock.Rule {
	var rules []landlock.Rule
	for _, r := range fsRules {
		access := landlockAdjustAccessForPath(r.Path, r.Access)
		if access == 0 {
			// A zero-access rule is a no-op; go-landlock errors on it.
			continue
		}
		if _, err := os.Stat(r.Path); err != nil {
			continue
		}
		rules = append(rules, landlock.PathAccess(
			landlock.AccessFSSet(access), r.Path,
		))
	}
	return rules
}
