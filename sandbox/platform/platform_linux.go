//go:build linux
// +build linux

package platform

import (
	"errors"

	"github.com/safedep/pmg/sandbox"
)

// NewSandbox creates a platform-specific sandbox instance for Linux.
// TODO: Implement Bubblewrap or seccomp-bpf based sandbox.
func NewSandbox() (sandbox.Sandbox, error) {
	return nil, errors.New("sandbox not yet implemented for Linux")
}
