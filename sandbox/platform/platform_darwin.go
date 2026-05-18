//go:build darwin
// +build darwin

package platform

import "github.com/safedep/pmg/sandbox"

// NewSandbox creates a platform-specific sandbox instance for macOS.
// Uses Seatbelt (sandbox-exec) for process isolation.
func NewSandbox() (sandbox.Sandbox, error) {
	return newSeatbeltSandbox()
}

// NewSeatbeltSandbox returns a Seatbelt-backed sandbox instance regardless of
// any platform-wide driver selection. Useful for per-driver diagnostics.
func NewSeatbeltSandbox() (sandbox.Sandbox, error) {
	return newSeatbeltSandbox()
}
