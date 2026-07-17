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

func NewYarnCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "yarn [action] [package]",
		Short:              "Guard yarn package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeYarnFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}
			return nil
		},
	}
}

func executeYarnFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandYarn()

	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultYarnPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create yarn package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
