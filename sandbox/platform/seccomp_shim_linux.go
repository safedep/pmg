//go:build linux

package platform

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// SeccompShimCommand is the hidden pmg command that bwrap runs in place of
// the target. The runner may start bwrap under a PTY, which passes no extra
// file descriptors, so bwrap cannot receive the filter by --seccomp.
const SeccompShimCommand = "__seccomp_shim"

// RunSeccompShim installs the sandbox seccomp filter and replaces itself with
// the target. It returns only on a failure before execve.
func RunSeccompShim(allowUnixSockets bool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("seccomp shim: no target command")
	}

	runtime.LockOSThread()

	filter := buildSeccompFilter(seccompFilterSpec{AllowUnixSockets: allowUnixSockets})
	if _, err := installSeccompFilter(filter, 0); err != nil {
		return fmt.Errorf("seccomp shim: %w", err)
	}

	if err := unix.Exec(args[0], args, os.Environ()); err != nil {
		return fmt.Errorf("seccomp shim: exec %s: %w", args[0], err)
	}
	return nil
}
