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

func NewBunCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "bun [action] [package]",
		Short:              "Guard bun package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeBunFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeBunFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandBun()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultBunPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create bun package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
