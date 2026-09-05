//go:build linux && !amd64 && !arm64

package platform

// No audit arch is known for this architecture, so the filter skips the
// arch check. PMG does not ship the Landlock driver here.
const seccompNativeArch = 0

const seccompX32SyscallBit = 0

func archPathSyscalls() map[uint32]pathSyscall {
	return nil
}
