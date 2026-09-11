//go:build windows
// +build windows

package platform

import (
	"errors"

	"github.com/safedep/pmg/sandbox"
)

// NewSandbox has no sandbox to create on Windows. Windows has no Landlock
// or Seatbelt equivalent that fits the policy model.
func NewSandbox() (sandbox.Sandbox, error) {
	return nil, errors.New("PMG has no sandbox on Windows")
}
