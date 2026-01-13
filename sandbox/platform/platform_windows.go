//go:build windows
// +build windows

package platform

import (
	"errors"

	"github.com/safedep/pmg/sandbox"
)

// NewSandbox creates a platform-specific sandbox instance for Windows.
func NewSandbox() (sandbox.Sandbox, error) {
	return nil, errors.New("sandbox not yet implemented for Windows")
}
