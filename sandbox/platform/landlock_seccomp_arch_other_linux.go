//go:build linux && !amd64 && !arm64

package platform

// No audit arch is known here, so the filter skips the arch check.
const seccompNativeArch = 0

const seccompX32SyscallBit = 0

func archPathSyscalls() map[uint32]pathSyscall {
	return nil
}
