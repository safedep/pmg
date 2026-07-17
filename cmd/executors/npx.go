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

func NewNpxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "npx [package] [action]",
		Short:              "Guard npx package executor",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeNpxFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeNpxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandNpx()
	packageExecutor, err := packagemanager.NewNpmPackageExecutor(packagemanager.DefaultNpxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create npx package executor proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageExecutor, args)
}
