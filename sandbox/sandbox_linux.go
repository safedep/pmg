//go:build linux
// +build linux

package sandbox

import "errors"

// newPlatformSandbox creates a platform-specific sandbox instance for Linux.
func newPlatformSandbox() (Sandbox, error) {
	return nil, errors.New("sandbox not yet implemented for Linux (coming soon: Bubblewrap or seccomp-bpf)")
}
