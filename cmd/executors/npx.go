package executors

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewNpxCommand() *cobra.Command {
	return newNpmExecutorCommand("npx [package] [action]", "Guard npx package executor",
		analytics.TrackCommandNpx, packagemanager.DefaultNpxPackageExecutorConfig())
}
