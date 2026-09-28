//go:build linux && !amd64 && !arm64

package platform

// No audit arch is known here, so the filter skips the arch check.
const seccompNativeArch = 0

const seccompX32SyscallBit = 0

// The argument checks need the amd64 and arm64 layout. PMG ships no other
// Linux architecture.
const seccompArgFiltering = false

func archDeniedSyscalls() []uint32 { return nil }

func archPathSyscalls() map[uint32]pathSyscall {
	return nil
}
