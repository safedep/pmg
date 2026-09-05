package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewAubeCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "aube [action] [package]",
		Short:              "Guard aube package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeAubeFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeAubeFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandAube()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultAubePackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create aube package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
