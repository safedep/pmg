//go:build linux

package platform

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompFilterSpec selects the parts of the sandbox seccomp filter that
// depend on the policy.
type seccompFilterSpec struct {
	// Notify lists the syscalls that return SECCOMP_RET_USER_NOTIF to the
	// Landlock supervisor. The Bubblewrap driver has no supervisor.
	Notify []uint32

	AllowUnixSockets bool
}

// Offsets into struct seccomp_data. The args start at 16. The low word of an
// argument comes first on the little-endian architectures PMG ships.
const (
	seccompDataNrOffset   = 0
	seccompDataArchOffset = 4
	seccompDataArg0Low    = 16
	seccompDataArg1Low    = 24
)

// seccompNewNamespaceFlags are the clone and unshare flags that create a
// namespace. CLONE_NEWTIME is 0x80, which clone(2) reads as the exit signal,
// so only unshare(2) checks it.
const seccompNewNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS |
	unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// seccompDeniedSyscalls return EPERM in the kernel for every sandboxed
// process. They load kernel code, change mounts or the clock, reach into
// another process's memory, or expose kernel attack surface that no package
// manager needs.
func seccompDeniedSyscalls() []uint32 {
	return append([]uint32{
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PROCESS_MADVISE, unix.SYS_PIDFD_GETFD,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT,
		unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR, unix.SYS_SETNS,
		unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_REBOOT, unix.SYS_ACCT,
		unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME,
		unix.SYS_SYSLOG, unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD,
		unix.SYS_LOOKUP_DCOOKIE, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_FANOTIFY_INIT, unix.SYS_VHANGUP,
	}, archDeniedSyscalls()...)
}

// buildSeccompFilter builds the classic BPF program for a sandboxed process.
//
// Order: a foreign or x32 ABI kills the process. clone3 returns ENOSYS
// because BPF cannot read its flags struct, and glibc then retries with
// clone. clone and unshare that create a namespace return EPERM. When unix
// sockets are blocked, socket(AF_UNIX) returns EACCES and so does a datagram
// socketpair, which can sendto(2) any datagram socket path. Then the denied
// group returns EPERM, the notify group goes to the supervisor, and every
// other syscall is allowed.
func buildSeccompFilter(spec seccompFilterSpec) []unix.SockFilter {
	var f []unix.SockFilter
	ld := func(k uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: k}
	}
	ret := func(k uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k}
	}
	errno := func(e unix.Errno) uint32 {
		return unix.SECCOMP_RET_ERRNO | (uint32(e) & unix.SECCOMP_RET_DATA)
	}

	if seccompNativeArch != 0 {
		f = append(f,
			ld(seccompDataArchOffset),
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: seccompNativeArch},
			ret(unix.SECCOMP_RET_KILL_PROCESS),
		)
	}
	f = append(f, ld(seccompDataNrOffset))
	if seccompX32SyscallBit != 0 {
		f = append(f,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: seccompX32SyscallBit},
			ret(unix.SECCOMP_RET_KILL_PROCESS),
		)
	}

	f = appendSyscallGroup(f, []uint32{unix.SYS_CLONE3}, errno(unix.ENOSYS))

	// argCheck returns action when nr is called and the masked argument
	// matches. It reloads nr for the checks that follow.
	argCheck := func(nr, argOffset, mask, value, action uint32) {
		test := unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: mask}
		body := []unix.SockFilter{ld(argOffset)}
		if value != 0 {
			body = append(body, unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: mask})
			test = unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: value}
		}
		body = append(body, test, ret(action), ld(seccompDataNrOffset))
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: uint8(len(body)), K: nr})
		f = append(f, body...)
	}

	if seccompArgFiltering {
		argCheck(unix.SYS_CLONE, seccompDataArg0Low, seccompNewNamespaceFlags, 0, errno(unix.EPERM))
		argCheck(unix.SYS_UNSHARE, seccompDataArg0Low, seccompNewNamespaceFlags|unix.CLONE_NEWTIME, 0, errno(unix.EPERM))
		if !spec.AllowUnixSockets {
			argCheck(unix.SYS_SOCKET, seccompDataArg0Low, 0xffffffff, unix.AF_UNIX, errno(unix.EACCES))
			argCheck(unix.SYS_SOCKETPAIR, seccompDataArg1Low, 0xf, unix.SOCK_DGRAM, errno(unix.EACCES))
		}
	}

	f = appendSyscallGroup(f, seccompDeniedSyscalls(), errno(unix.EPERM))
	f = appendSyscallGroup(f, spec.Notify, unix.SECCOMP_RET_USER_NOTIF)
	return append(f, ret(unix.SECCOMP_RET_ALLOW))
}

// appendSyscallGroup emits one JEQ per syscall that jumps to a shared RET,
// and a JA over that RET for the fall-through.
func appendSyscallGroup(f []unix.SockFilter, syscalls []uint32, action uint32) []unix.SockFilter {
	n := len(syscalls)
	if n == 0 {
		return f
	}
	if n > 255 {
		panic(fmt.Sprintf("seccomp filter: %d syscalls exceed the BPF jump range", n))
	}
	for i, nr := range syscalls {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: uint8(n - i), K: nr})
	}
	return append(f,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA, K: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: action},
	)
}

// installSeccompFilter sets PR_SET_NO_NEW_PRIVS and loads the filter on the
// calling thread. The caller must lock the OS thread and execve from it,
// because the filter is not synchronized to other threads.
func installSeccompFilter(filter []unix.SockFilter, flags uintptr) (int, error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}
	prog := &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(prog)))
	runtime.KeepAlive(prog)
	runtime.KeepAlive(filter)
	if errno != 0 {
		return -1, fmt.Errorf("SECCOMP_SET_MODE_FILTER: %w", errno)
	}
	return int(fd), nil
}
