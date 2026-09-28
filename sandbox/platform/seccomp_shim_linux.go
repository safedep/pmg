//go:build linux

package platform

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// SeccompShimCommand is the hidden pmg command that bwrap runs before the
// target. bwrap --seccomp cannot work, because a PTY run passes no extra
// file descriptors.
const SeccompShimCommand = "__seccomp_shim"

// SeccompShimConfig holds the policy switches of the seccomp shim.
type SeccompShimConfig struct {
	AllowUnixSockets bool
}

// RunSeccompShim installs the seccomp filter and execs execArgs. It returns
// only when a step before execve fails.
func RunSeccompShim(cfg SeccompShimConfig, execArgs []string) error {
	if len(execArgs) == 0 {
		return fmt.Errorf("seccomp shim: no target command")
	}

	runtime.LockOSThread()

	filter := buildSeccompFilter(seccompFilterSpec{AllowUnixSockets: cfg.AllowUnixSockets})
	if _, err := installSeccompFilter(filter, 0); err != nil {
		return fmt.Errorf("seccomp shim: %w", err)
	}

	if err := unix.Exec(execArgs[0], execArgs, os.Environ()); err != nil {
		return fmt.Errorf("seccomp shim: exec %s: %w", execArgs[0], err)
	}
	return nil
}
