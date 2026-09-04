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

func NewPnpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pnpm [action] [package]",
		Short:              "Guard pnpm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePnpmFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePnpmFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPnpm()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultPnpmPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pnpm package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
