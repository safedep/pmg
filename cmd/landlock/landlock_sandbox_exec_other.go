//go:build !linux

package landlock

import "github.com/spf13/cobra"

// NewLandlockSandboxExecCommand returns nil on non-Linux platforms where
// Landlock is not available.
func NewLandlockSandboxExecCommand() *cobra.Command { return nil }
