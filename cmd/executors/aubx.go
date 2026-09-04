package executors

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

// NewAubxCommand guards aubx, the aube shorthand for `aube dlx`.
func NewAubxCommand() *cobra.Command {
	return newNpmExecutorCommand("aubx [package] [action]", "Guard aubx package executor (aube dlx)",
		analytics.TrackCommandAubx, packagemanager.DefaultAubxPackageExecutorConfig())
}
