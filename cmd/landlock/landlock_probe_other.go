//go:build !linux

package landlock

import "github.com/spf13/cobra"

// NewLandlockProbeCommand returns nil on non-Linux platforms.
func NewLandlockProbeCommand() *cobra.Command { return nil }
