package npm

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPnpmCommand() *cobra.Command {
	return newProxyCommand("pnpm [action] [package]", "Guard pnpm package manager",
		analytics.TrackCommandPnpm, packagemanager.DefaultPnpmPackageManagerConfig())
}
