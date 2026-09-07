//go:build linux && amd64

package platform

import "golang.org/x/sys/unix"

// seccompNativeArch is the audit arch the filter accepts. A syscall from
// another ABI (int 0x80, x32) carries other numbers and kills the process.
const seccompNativeArch = unix.AUDIT_ARCH_X86_64

// seccompX32SyscallBit marks an x32 syscall number under AUDIT_ARCH_X86_64.
const seccompX32SyscallBit = 0x40000000

// archPathSyscalls lists the path syscalls that not every Linux architecture
// has. musl and raw syscall(2) callers use the legacy forms.
func archPathSyscalls() map[uint32]pathSyscall {
	return map[uint32]pathSyscall{
		unix.SYS_RENAMEAT: {name: "renameat", kind: pathOpRename, src: pathOperand{dirfd: 0, path: 1}, dst: pathOperand{dirfd: 2, path: 3}, flags: -1},
		unix.SYS_OPEN:     {name: "open", kind: pathOpOpen, src: pathOperand{dirfd: -1, path: 0}, flags: 1},
		unix.SYS_CREAT:    {name: "creat", kind: pathOpOpen, src: pathOperand{dirfd: -1, path: 0}, flags: -1, fixedFlags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC},
		unix.SYS_RENAME:   {name: "rename", kind: pathOpRename, src: pathOperand{dirfd: -1, path: 0}, dst: pathOperand{dirfd: -1, path: 1}, flags: -1},
		unix.SYS_LINK:     {name: "link", kind: pathOpLink, src: pathOperand{dirfd: -1, path: 0}, dst: pathOperand{dirfd: -1, path: 1}, flags: -1},
		unix.SYS_UNLINK:   {name: "unlink", kind: pathOpRemove, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
		unix.SYS_RMDIR:    {name: "rmdir", kind: pathOpRemove, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
		unix.SYS_MKDIR:    {name: "mkdir", kind: pathOpCreate, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
		unix.SYS_MKNOD:    {name: "mknod", kind: pathOpCreate, src: pathOperand{dirfd: -1, path: 0}, flags: -1},
		unix.SYS_SYMLINK:  {name: "symlink", kind: pathOpSymlink, src: pathOperand{dirfd: -1, path: 1}, flags: -1},
	}
}
