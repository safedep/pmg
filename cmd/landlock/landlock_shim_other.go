//go:build !linux

package landlock

import "github.com/spf13/cobra"

// NewLandlockShimCommand returns nil on non-Linux platforms.
func NewLandlockShimCommand() *cobra.Command { return nil }
