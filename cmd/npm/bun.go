package npm

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewBunCommand() *cobra.Command {
	return newProxyCommand("bun [action] [package]", "Guard bun package manager",
		analytics.TrackCommandBun, packagemanager.DefaultBunPackageManagerConfig())
}
