//go:build linux && arm64

package platform

import "golang.org/x/sys/unix"

// seccompNativeArch is the audit arch the filter accepts. See the amd64 file.
const seccompNativeArch = unix.AUDIT_ARCH_AARCH64

// arm64 has no x32-style compat ABI on the native syscall table.
const seccompX32SyscallBit = 0

// archPathSyscalls adds renameat, which the generic table leaves out because
// riscv64 has only renameat2.
func archPathSyscalls() map[uint32]pathSyscall {
	return map[uint32]pathSyscall{
		unix.SYS_RENAMEAT: {name: "renameat", kind: pathOpRename, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: -1},
	}
}
