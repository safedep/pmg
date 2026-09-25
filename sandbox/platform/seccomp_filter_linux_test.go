//go:build linux

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// runSeccompFilter interprets the classic BPF subset the builder emits
// against one seccomp_data, so the tests check decisions, not layout.
func runSeccompFilter(t *testing.T, filter []unix.SockFilter, arch, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	word := func(k uint32) uint32 {
		switch {
		case k == seccompDataNrOffset:
			return nr
		case k == seccompDataArchOffset:
			return arch
		case k >= 16 && k < 64 && k%4 == 0:
			arg := args[(k-16)/8]
			if (k-16)%8 == 0 {
				return uint32(arg)
			}
			return uint32(arg >> 32)
		}
		require.Failf(t, "bad load offset", "k=%d", k)
		return 0
	}

	var acc uint32
	for pc := 0; pc < len(filter); pc++ {
		ins := filter[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = word(ins.K)
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			acc &= ins.K
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(ins.K)
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			var hit bool
			switch ins.Code &^ (unix.BPF_JMP | unix.BPF_K) {
			case unix.BPF_JEQ:
				hit = acc == ins.K
			case unix.BPF_JGE:
				hit = acc >= ins.K
			case unix.BPF_JSET:
				hit = acc&ins.K != 0
			}
			if hit {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			require.Failf(t, "unknown instruction", "code=%#x at %d", ins.Code, pc)
		}
		require.Less(t, pc, len(filter), "jump past the end of the program")
	}
	require.Fail(t, "program fell off the end")
	return 0
}

func seccompErrno(e unix.Errno) uint32 {
	return unix.SECCOMP_RET_ERRNO | uint32(e)
}

func TestBuildSeccompFilter(t *testing.T) {
	if !seccompArgFiltering {
		t.Skip("argument checks are off on this architecture")
	}
	notify := []uint32{unix.SYS_EXECVE, unix.SYS_OPENAT, unix.SYS_CONNECT}
	blocked := buildSeccompFilter(seccompFilterSpec{Notify: notify})
	allowed := buildSeccompFilter(seccompFilterSpec{Notify: notify, AllowUnixSockets: true})
	require.Less(t, len(blocked), 4096)

	arch := uint32(seccompNativeArch)
	a := func(v ...uint64) [6]uint64 {
		var out [6]uint64
		copy(out[:], v)
		return out
	}
	threadFlags := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD)

	tests := []struct {
		name   string
		filter []unix.SockFilter
		nr     uint32
		args   [6]uint64
		want   uint32
	}{
		{"read allowed", blocked, unix.SYS_READ, a(), unix.SECCOMP_RET_ALLOW},
		{"clone3 falls back to clone", blocked, unix.SYS_CLONE3, a(), seccompErrno(unix.ENOSYS)},
		{"clone thread allowed", blocked, unix.SYS_CLONE, a(threadFlags), unix.SECCOMP_RET_ALLOW},
		{"clone fork allowed", blocked, unix.SYS_CLONE, a(uint64(unix.SIGCHLD)), unix.SECCOMP_RET_ALLOW},
		{"clone new user namespace denied", blocked, unix.SYS_CLONE, a(unix.CLONE_NEWUSER | uint64(unix.SIGCHLD)), seccompErrno(unix.EPERM)},
		{"clone new net namespace denied", blocked, unix.SYS_CLONE, a(unix.CLONE_NEWNET), seccompErrno(unix.EPERM)},
		{"clone high word ignored", blocked, unix.SYS_CLONE, a(1 << 40), unix.SECCOMP_RET_ALLOW},
		{"unshare files allowed", blocked, unix.SYS_UNSHARE, a(unix.CLONE_FILES | unix.CLONE_FS), unix.SECCOMP_RET_ALLOW},
		{"unshare mount namespace denied", blocked, unix.SYS_UNSHARE, a(unix.CLONE_NEWNS), seccompErrno(unix.EPERM)},
		{"unshare time namespace denied", blocked, unix.SYS_UNSHARE, a(unix.CLONE_NEWTIME), seccompErrno(unix.EPERM)},
		{"socket unix denied", blocked, unix.SYS_SOCKET, a(unix.AF_UNIX, unix.SOCK_STREAM), seccompErrno(unix.EACCES)},
		{"socket unix allowed by profile", allowed, unix.SYS_SOCKET, a(unix.AF_UNIX, unix.SOCK_STREAM), unix.SECCOMP_RET_ALLOW},
		{"socket inet allowed", blocked, unix.SYS_SOCKET, a(unix.AF_INET, unix.SOCK_STREAM), unix.SECCOMP_RET_ALLOW},
		{"socket netlink allowed", blocked, unix.SYS_SOCKET, a(unix.AF_NETLINK, unix.SOCK_RAW), unix.SECCOMP_RET_ALLOW},
		{"stream socketpair allowed", blocked, unix.SYS_SOCKETPAIR, a(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC), unix.SECCOMP_RET_ALLOW},
		{"datagram socketpair denied", blocked, unix.SYS_SOCKETPAIR, a(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC), seccompErrno(unix.EACCES)},
		{"datagram socketpair allowed by profile", allowed, unix.SYS_SOCKETPAIR, a(unix.AF_UNIX, unix.SOCK_DGRAM), unix.SECCOMP_RET_ALLOW},
		{"execve notifies", blocked, unix.SYS_EXECVE, a(), unix.SECCOMP_RET_USER_NOTIF},
		{"connect notifies", blocked, unix.SYS_CONNECT, a(), unix.SECCOMP_RET_USER_NOTIF},
		{"io_uring denied", blocked, unix.SYS_IO_URING_SETUP, a(), seccompErrno(unix.EPERM)},
	}
	for _, nr := range seccompDeniedSyscalls() {
		tests = append(tests, struct {
			name   string
			filter []unix.SockFilter
			nr     uint32
			args   [6]uint64
			want   uint32
		}{syscallDeniedName(nr), blocked, nr, a(), seccompErrno(unix.EPERM)})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, runSeccompFilter(t, tc.filter, arch, tc.nr, tc.args))
		})
	}
}

func TestBuildSeccompFilter_ABIGuards(t *testing.T) {
	if seccompNativeArch == 0 {
		t.Skip("no native audit arch on this architecture")
	}
	filter := buildSeccompFilter(seccompFilterSpec{})

	assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS),
		runSeccompFilter(t, filter, unix.AUDIT_ARCH_I386, unix.SYS_READ, [6]uint64{}))
	if seccompX32SyscallBit != 0 {
		assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS),
			runSeccompFilter(t, filter, seccompNativeArch, seccompX32SyscallBit|unix.SYS_READ, [6]uint64{}))
	}
}

func TestBuildSeccompFilter_NoNotifyGroup(t *testing.T) {
	filter := buildSeccompFilter(seccompFilterSpec{})
	assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW),
		runSeccompFilter(t, filter, seccompNativeArch, unix.SYS_EXECVE, [6]uint64{}))
}

func syscallDeniedName(nr uint32) string {
	return "denied syscall " + syscallName(int32(nr))
}
