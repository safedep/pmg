package npm

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewNpmCommand() *cobra.Command {
	return newProxyCommand("npm [action] [package]", "Guard npm package manager",
		analytics.TrackCommandNpm, packagemanager.DefaultNpmPackageManagerConfig())
}
