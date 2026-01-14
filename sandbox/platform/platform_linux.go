//go:build linux
// +build linux

package platform

import (
	"github.com/safedep/pmg/sandbox"
)

// NewSandbox creates a platform-specific sandbox instance for Linux.
// Uses Bubblewrap (bwrap) for filesystem, network, and process isolation.
func NewSandbox() (sandbox.Sandbox, error) {
	return newBubblewrapSandbox()
}
