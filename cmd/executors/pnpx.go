package executors

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPnpxCommand() *cobra.Command {
	return newNpmExecutorCommand("pnpx [package] [action]", "Guard pnpx package executor",
		analytics.TrackCommandPnpx, packagemanager.DefaultPnpxPackageExecutorConfig())
}
