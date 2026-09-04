package npm

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewYarnCommand() *cobra.Command {
	return newProxyCommand("yarn [action] [package]", "Guard yarn package manager",
		analytics.TrackCommandYarn, packagemanager.DefaultYarnPackageManagerConfig())
}
