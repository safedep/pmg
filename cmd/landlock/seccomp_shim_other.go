//go:build !linux

package landlock

import "github.com/spf13/cobra"

// NewSeccompShimCommand returns nil on non-Linux platforms.
func NewSeccompShimCommand() *cobra.Command { return nil }
