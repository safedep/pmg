package npm

import (
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewAubeCommand() *cobra.Command {
	return newProxyCommand("aube [action] [package]", "Guard aube package manager",
		analytics.TrackCommandAube, packagemanager.DefaultAubePackageManagerConfig())
}

// NewAubrCommand guards aubr, the aube shorthand for `aube run`. A script run
// installs missing or stale dependencies first.
func NewAubrCommand() *cobra.Command {
	return newProxyCommand("aubr [script] [args]", "Guard aubr script runner (aube run)",
		analytics.TrackCommandAubr, packagemanager.DefaultAubrPackageManagerConfig())
}
