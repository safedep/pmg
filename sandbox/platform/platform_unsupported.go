//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package platform

import (
	"errors"

	"github.com/safedep/pmg/sandbox"
)

// NewSandbox returns an error on unsupported platforms.
func NewSandbox() (sandbox.Sandbox, error) {
	return nil, errors.New("sandbox not supported on this platform")
}
