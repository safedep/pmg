package pypi

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPip3Command() *cobra.Command {
	return &cobra.Command{
		Use:                "pip3 [action] [package]",
		Short:              "Guard pip3 package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePip3Flow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePip3Flow(ctx context.Context, args []string) error {
	analytics.TrackCommandPip3()
	packageManager, err := packagemanager.NewPypiPackageManager(packagemanager.DefaultPip3PackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pip3 package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
