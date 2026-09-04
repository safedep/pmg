package executors

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPnpxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pnpx [package] [action]",
		Short:              "Guard pnpx package executor",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePnpxFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePnpxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPnpx()
	packageExecutor, err := packagemanager.NewNpmPackageExecutor(packagemanager.DefaultPnpxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create pnpx package executor proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageExecutor, args)
}
